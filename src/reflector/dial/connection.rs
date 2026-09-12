//! One proxied client↔device connection: the bidirectional HTTP byte splice.
//!
//! Each [`Connection`] pairs two sockets with a per-direction [`Flow`] (an HTTP framer plus a receive
//! and a send buffer), driven on the reactor's readable/writable edges. A readable edge frames whole
//! messages out of the source, rewrites their authority headers per the direction's policy (the
//! request's `Host` to the device; the response's `Application-URL`/`Location` to the proxy's listeners,
//! so the device's address never leaks), and forwards them; a writable edge drains the backlog. Each
//! direction half-closes independently: a source's EOF flushes its remaining bytes and FINs the peer
//! while the reverse direction keeps flowing, and the connection closes once both directions are `Done`.
//! Backpressure is drop-and-close: a send-buffer overflow tears the connection down rather than
//! throttling the reader.

use std::io;
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::net::http::framing::{HttpFraming, Kind, RewritePolicy};
use crate::net::stream_buffer::StreamBuffer;
use crate::net::tcp::TcpSocket;
use crate::reactor::{Reactor, RegKey};
use crate::sys::IoStatus;

/// Per-connection, per-direction receive buffer: one read chunk plus header accumulation.
const MAX_RECV: usize = 4 * 1024;
/// Per-connection, per-direction send buffer: the unsent tail held under backpressure; past it the
/// connection drops-and-closes.
const MAX_SEND: usize = 8 * 1024;
/// A non-blocking device connect must complete within this.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// An open connection idle this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Must exceed the framer's header cap, or the over-cap refusal can't fire before the buffer fills and
/// the always-armed reader livelocks.
const _: () = assert!(MAX_RECV > crate::net::http::framing::MAX_HEADER);

/// A direction's half-close progress. `Open` while both ends are live; `SourceClosed` once the source
/// sent EOF and the buffered tail is still flushing toward the destination; `Done` once that flush
/// completes and our write to the destination is shut. A connection closes once both are `Done`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FlowState {
    Open,
    SourceClosed,
    Done,
}

/// One direction of the duplex splice: its HTTP framer, recv/send buffers, and half-close state.
struct Flow {
    framer: HttpFraming,
    recv: StreamBuffer,
    send: StreamBuffer,
    state: FlowState,
}

impl Flow {
    /// A flow framing `kind` messages, rewriting their authority headers per `rewrite`.
    fn new(kind: Kind, rewrite: RewritePolicy) -> Self {
        Self {
            framer: HttpFraming::new(kind, rewrite),
            recv: StreamBuffer::with_capacity(MAX_RECV),
            send: StreamBuffer::with_capacity(MAX_SEND),
            state: FlowState::Open,
        }
    }
}

/// Which way bytes flow on one edge of the splice. `ClientToDevice` is the `c2u` flow (request →
/// device, `Host` rewritten to the device); `DeviceToClient` is `u2c` (response → client,
/// `Application-URL`/`Location` rewritten to the proxy's listeners so the device's address never leaks).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToDevice,
    DeviceToClient,
}

/// The keep/close decision the per-edge handlers return.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Outcome {
    Keep,
    Close,
}

/// What one [`DirectionContext::forward`] pass concluded: more may follow (`Open`), the source
/// half-closed so flush-then-finish (`SourceEof`), or a fatal error (`Failed`).
enum Forwarded {
    Open,
    SourceEof,
    Failed,
}

/// One `Direction` resolved against a connection: the read/forward sockets and their registrations, this
/// direction's flow, a slot for any REST endpoint learned from a response, and the deadline. Built once
/// per event by [`Connection::context`] so the forward/drain paths never re-pick a side.
struct DirectionContext<'a> {
    from: &'a TcpSocket,
    from_reg: Option<RegKey>,
    to: &'a TcpSocket,
    to_reg: Option<RegKey>,
    flow: &'a mut Flow,
    learned_rest: &'a mut Option<SocketAddrV4>,
    deadline: &'a mut Instant,
}

impl DirectionContext<'_> {
    /// Read one chunk from the source, frame whole messages out of it, rewrite each per this direction's
    /// policy, and forward to the destination, buffering any unsent tail for the writable edge to drain.
    /// The deadline is refreshed only when bytes actually reach the destination, so a wedged connection
    /// still ages out via the idle sweep. A framing/recv/send error or a backpressure overflow is
    /// `Failed`; the source half-closed is `SourceEof`; otherwise `Open`. Reactor-free, so the splice is
    /// unit-testable.
    fn forward(&mut self) -> Forwarded {
        let tail = self.flow.recv.free_tail_mut();
        if tail.is_empty() {
            log::warn!("dial: receive buffer full of an unframable message; closing");
            return Forwarded::Failed;
        }
        let n = match self.from.recv(tail) {
            Ok(IoStatus::Ready(0)) => return Forwarded::SourceEof, // the peer half-closed its write
            Ok(IoStatus::Ready(n)) => n,
            Ok(IoStatus::WouldBlock) => return Forwarded::Open, // a spurious wake, nothing new
            Err(e) => {
                log::debug!("dial: recv failed: {e}");
                return Forwarded::Failed;
            }
        };
        self.flow.recv.commit(n);
        loop {
            let framed = match self.flow.framer.feed(self.flow.recv.pending()) {
                Ok(framed) => framed,
                Err(e) => {
                    log::debug!("dial: framing error: {e:?}");
                    return Forwarded::Failed;
                }
            };
            // Learn the device REST base from a response's Application-URL; a later description fetch can
            // move it, so the latest message wins. Only the response framer reports it, so this can't
            // fire on the client→device side, where the endpoint would be the client's to choose.
            if let Some(ep) = framed.application_url {
                *self.learned_rest = Some(ep);
            }
            if framed.consumed == 0 {
                break; // an incomplete message: wait for more bytes
            }
            let consumed = framed.consumed;
            if send_framed(
                self.to,
                &mut self.flow.send,
                framed.header,
                framed.body,
                self.deadline,
            ) == Outcome::Close
            {
                return Forwarded::Failed;
            }
            self.flow.recv.consume(consumed);
        }
        Forwarded::Open
    }

    /// The source half-closed (sent EOF): disarm its read interest (its FIN is now permanently readable,
    /// so disarming keeps it from re-firing), mark the flow `SourceClosed`, then settle. The
    /// destination stays open and writable, so the reverse direction keeps delivering. `Close` if the
    /// reactor rejects the disarm.
    fn half_close(&mut self, reactor: &mut Reactor) -> Outcome {
        // Reached only while the flow is Open, and peer_gone marks a flow Done before taking that
        // side's reg, so this side's is still set.
        let reg = self
            .from_reg
            .expect("an open flow's source keeps its registration");
        if reactor.set_read_interest(reg, false).is_err() {
            log::warn!("dial: disarming the half-closed source failed; closing");
            return Outcome::Close;
        }
        self.flow.state = FlowState::SourceClosed;
        self.settle(reactor)
    }

    /// Settle a flow after a forward or drain: if its source has closed and its backlog is now flushed,
    /// FIN the destination and mark the flow `Done`; then arm the destination's write interest to
    /// whatever backlog remains. A fully-drained flow disarms it, so `on_writable` never re-enters here
    /// and the FIN fires exactly once. `Close` if the reactor rejects the change.
    fn settle(&mut self, reactor: &mut Reactor) -> Outcome {
        // Defer finishing while the destination is still connecting: `shutdown_write` would be an
        // `ENOTCONN` no-op (the FIN lost) and `Done` a lie. The connect-completion edge (kept armed by
        // `sync_write_interest` below) drives `finish_connect`, after which a later settle finishes.
        if self.flow.state == FlowState::SourceClosed
            && self.flow.send.is_empty()
            && !self.to.is_connecting()
        {
            self.to.shutdown_write();
            self.flow.state = FlowState::Done;
        }
        self.sync_write_interest(reactor)
    }

    /// Drain as much of this direction's send backlog as the destination will take now, refreshing the
    /// deadline on real progress. `Close` on a send error; otherwise `Keep` (the caller re-evaluates
    /// write interest).
    fn drain(&mut self) -> Outcome {
        if self.flow.send.is_empty() {
            return Outcome::Keep;
        }
        match self.to.send(self.flow.send.pending()) {
            Ok(IoStatus::Ready(n)) => {
                self.flow.send.consume(n);
                if n > 0 {
                    *self.deadline = Instant::now() + IDLE_TIMEOUT;
                }
                Outcome::Keep
            }
            Ok(IoStatus::WouldBlock) => Outcome::Keep,
            Err(e) => {
                log::debug!("dial: draining send to peer failed: {e}");
                Outcome::Close
            }
        }
    }

    /// Arm the destination's write interest iff it has a send backlog, or while it is still connecting so
    /// the connect-completion edge (a writable edge with no backlog) survives. `Close` if the reactor
    /// rejects the change, which would otherwise strand the buffered send with no later re-arm.
    fn sync_write_interest(&self, reactor: &mut Reactor) -> Outcome {
        let armed = !self.flow.send.is_empty() || self.to.is_connecting();
        // As in half_close: an Open flow means no peer_gone has taken this direction's regs.
        let reg = self
            .to_reg
            .expect("an open flow's destination keeps its registration");
        if reactor.set_write_interest(reg, armed).is_err() {
            log::warn!("dial: updating write interest failed; closing");
            return Outcome::Close;
        }
        Outcome::Keep
    }
}

/// One proxied client↔device connection. Each socket is watched under its own reg; `device_endpoint`
/// is where `device` connects and the `Host` rewrite target. `deadline` is the connect timeout while
/// the device connect is in flight, then the idle timeout. A reg is `None` before
/// [`attach_registrations`](Self::attach_registrations) runs, and again once
/// [`peer_gone`](Self::peer_gone) takes the hung-up side's: the connection outlives that, and
/// [`forward`](Self::forward) reads the `None` as "a prior `peer_gone` took it".
pub(super) struct Connection {
    client: TcpSocket,
    client_reg: Option<RegKey>,
    device: TcpSocket,
    device_reg: Option<RegKey>,
    device_endpoint: SocketAddrV4,
    c2u: Flow, // client -> device
    u2c: Flow, // device -> client
    /// The device REST endpoint just learned from a response's `Application-URL`, lifted into the proxy's
    /// `rest_endpoint` after each readable edge (`None` between).
    learned_rest: Option<SocketAddrV4>,
    deadline: Instant,
}

impl Connection {
    /// A new proxied connection from `client` to the device at `device_endpoint`. The request rewrites
    /// its `Host` to the device; the response rewrites `Application-URL` to `rest_listener` and
    /// `Location` to `own_listener`, so the device never leaks. Registrations are `None` until
    /// [`attach_registrations`](Self::attach_registrations); the deadline starts as the connect timeout.
    pub(super) fn new(
        client: TcpSocket,
        device: TcpSocket,
        device_endpoint: SocketAddrV4,
        rest_listener: SocketAddrV4,
        own_listener: SocketAddrV4,
    ) -> Self {
        let c2u_rewrite = RewritePolicy {
            host: Some(device_endpoint),
            application_url: None,
            location: None,
        };
        let u2c_rewrite = RewritePolicy {
            host: None,
            application_url: Some(rest_listener),
            location: Some(own_listener),
        };
        Self {
            client,
            client_reg: None,
            device,
            device_reg: None,
            device_endpoint,
            c2u: Flow::new(Kind::Request, c2u_rewrite),
            u2c: Flow::new(Kind::Response, u2c_rewrite),
            learned_rest: None,
            deadline: Instant::now() + CONNECT_TIMEOUT,
        }
    }

    /// Record the per-fd registrations once both sockets are watched.
    pub(super) fn attach_registrations(&mut self, client_reg: RegKey, device_reg: RegKey) {
        self.client_reg = Some(client_reg);
        self.device_reg = Some(device_reg);
    }

    /// The device endpoint this connection targets: its `Host` rewrite target and log identity.
    pub(super) fn device_endpoint(&self) -> SocketAddrV4 {
        self.device_endpoint
    }

    /// This connection's current deadline (the connect timeout, then the idle timeout).
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Take any REST endpoint just learned from a response's `Application-URL`, for the proxy to lift
    /// into its `rest_endpoint`.
    pub(super) fn take_learned_rest(&mut self) -> Option<SocketAddrV4> {
        self.learned_rest.take()
    }

    /// The readable `fd` has bytes: forward one edge. The readable fd is the source, so reading the client
    /// forwards to the device (`c2u`).
    pub(super) fn readable(&mut self, fd: RawFd, reactor: &mut Reactor) -> Outcome {
        let direction = if self.client.as_raw_fd() == fd {
            Direction::ClientToDevice
        } else {
            Direction::DeviceToClient
        };
        self.forward(direction, reactor)
    }

    /// The writable `fd` can take more: complete the connect / drain its send backlog. The writable fd
    /// is the destination, so draining toward the device is the `c2u` flow's send.
    pub(super) fn writable(&mut self, fd: RawFd, reactor: &mut Reactor) -> Outcome {
        let direction = if self.device.as_raw_fd() == fd {
            Direction::ClientToDevice
        } else {
            Direction::DeviceToClient
        };
        self.on_writable(direction, reactor)
    }

    /// Drop both watched fds' kernel interest, then shut both sockets down. Either reg may be `None`:
    /// a half-built connection has neither yet, and a `peer_gone` has taken the hung-up side's.
    pub(super) fn teardown(self, reactor: &mut Reactor) {
        if let Some(reg) = self.client_reg {
            reactor.unwatch(reg).ok();
        }
        if let Some(reg) = self.device_reg {
            reactor.unwatch(reg).ok();
        }
        self.client.shutdown();
        self.device.shutdown();
    }

    /// The resolved [`DirectionContext`] for `direction`.
    fn context(&mut self, direction: Direction) -> DirectionContext<'_> {
        match direction {
            Direction::ClientToDevice => DirectionContext {
                from: &self.client,
                from_reg: self.client_reg,
                to: &self.device,
                to_reg: self.device_reg,
                flow: &mut self.c2u,
                learned_rest: &mut self.learned_rest,
                deadline: &mut self.deadline,
            },
            Direction::DeviceToClient => DirectionContext {
                from: &self.device,
                from_reg: self.device_reg,
                to: &self.client,
                to_reg: self.client_reg,
                flow: &mut self.u2c,
                learned_rest: &mut self.learned_rest,
                deadline: &mut self.deadline,
            },
        }
    }

    /// Fold a per-direction `outcome` into the connection's: an explicit `Close`, or close once both
    /// directions are `Done`; otherwise keep.
    fn close_if_complete(&self, outcome: Outcome) -> Outcome {
        if outcome == Outcome::Close
            || (self.c2u.state == FlowState::Done && self.u2c.state == FlowState::Done)
        {
            Outcome::Close
        } else {
            Outcome::Keep
        }
    }

    /// `direction`'s source peer has fully hung up. Whatever it already sent may still be buffered toward
    /// the *other*, still-live peer, so finish delivering that (`settle` drains it asynchronously, then
    /// FINs). The reverse direction is dead (its destination is the vanished peer), so abandon it
    /// (`Done`, dropping its undeliverable buffer) and disarm its source read, lest a stray edge re-enter
    /// and tear us down early. Unwatch the vanished fd, whose level-triggered HUP would otherwise re-fire
    /// every wait. The connection closes once the forward flow finishes draining.
    fn peer_gone(&mut self, direction: Direction, reactor: &mut Reactor) -> Outcome {
        log::debug!(
            "dial: {} hung up on the connection to {}",
            match direction {
                Direction::ClientToDevice => "client",
                Direction::DeviceToClient => "device",
            },
            self.device_endpoint
        );
        // The abandoned reverse flow's source is the reg to disarm; the hung-up fd is the reg to unwatch.
        // The guard routes here only with a live destination reg, and the source's reg is still set (its
        // fd just hung up, and peer_gone (which takes it) runs once), so both expects hold.
        let (disarm_reg, unwatch_reg) = match direction {
            Direction::ClientToDevice => {
                self.u2c.state = FlowState::Done; // the response can't reach the gone client
                (
                    self.device_reg
                        .expect("a live destination keeps its registration"),
                    self.client_reg
                        .take()
                        .expect("the hung-up source still has its registration"),
                )
            }
            Direction::DeviceToClient => {
                self.c2u.state = FlowState::Done; // the request can't reach the gone device
                (
                    self.client_reg
                        .expect("a live destination keeps its registration"),
                    self.device_reg
                        .take()
                        .expect("the hung-up source still has its registration"),
                )
            }
        };
        // A failure here is rare (a reactor syscall on a live fd), but ignoring it is unsafe: a
        // still-watched hung-up fd would re-fire its HUP, re-enter here, and find its reg already taken.
        if reactor.set_read_interest(disarm_reg, false).is_err()
            || reactor.unwatch(unwatch_reg).is_err()
        {
            log::warn!("dial: winding down a hung-up peer failed; closing");
            return Outcome::Close;
        }
        if self.context(direction).settle(reactor) == Outcome::Close {
            return Outcome::Close;
        }
        self.close_if_complete(Outcome::Keep)
    }

    /// Forward one readable edge in `direction`: splice the bytes, then on the source's EOF begin its
    /// half-close, on a fatal error tear down, otherwise arm the destination's write interest.
    fn forward(&mut self, direction: Direction, reactor: &mut Reactor) -> Outcome {
        let mut ctx = self.context(direction);
        // A non-Open flow means we already disarmed this source's read when it half-closed, yet it woke
        // us again. Only a hangup/reset does that, since epoll delivers HUP/ERR regardless of the read
        // mask. The source peer is fully gone. If its destination is gone too (a prior `peer_gone` took
        // that reg, leaving it `None`), both peers have vanished, so close. Otherwise wind down, finishing
        // any backlog still owed to the live destination, rather than re-running the half-close.
        if ctx.flow.state != FlowState::Open {
            return if ctx.to_reg.is_none() {
                Outcome::Close
            } else {
                self.peer_gone(direction, reactor)
            };
        }
        let forwarded = ctx.forward();
        let outcome = match forwarded {
            Forwarded::Failed => Outcome::Close,
            Forwarded::SourceEof => ctx.half_close(reactor),
            Forwarded::Open => ctx.sync_write_interest(reactor),
        };
        self.close_if_complete(outcome)
    }

    /// A connection socket is writable: complete the device connect if still pending, drain `direction`'s
    /// send backlog, then settle its half-close. `Close` to tear down.
    fn on_writable(&mut self, direction: Direction, reactor: &mut Reactor) -> Outcome {
        if direction == Direction::ClientToDevice && self.device.is_connecting() {
            match self.device.finish_connect() {
                Ok(()) => {
                    log::debug!("dial: connected to {}", self.device_endpoint);
                    self.deadline = Instant::now() + IDLE_TIMEOUT;
                }
                Err(e) => {
                    log::warn!(
                        "dial: device connect to {} failed: {e}",
                        self.device_endpoint
                    );
                    return Outcome::Close;
                }
            }
        }
        let mut ctx = self.context(direction);
        if ctx.drain() == Outcome::Close {
            return Outcome::Close;
        }
        let outcome = ctx.settle(reactor);
        self.close_if_complete(outcome)
    }
}

/// Send `header` then `body` to `to`, preserving order: if `to` already has a backlog or is still
/// connecting, the whole message is buffered; otherwise it goes out in one scatter-gather write and
/// only the unsent tail is buffered. Refreshes `deadline` when bytes reach the socket. `Close` on a send
/// error or a buffer overflow (drop-and-close backpressure; the reader is never throttled).
fn send_framed(
    to: &TcpSocket,
    to_send: &mut StreamBuffer,
    header: &[u8],
    body: &[u8],
    deadline: &mut Instant,
) -> Outcome {
    if !to_send.is_empty() || to.is_connecting() {
        return buffer_tail(to_send, header, body);
    }
    let total = header.len() + body.len();
    let sent = match to.send_vectored(&[io::IoSlice::new(header), io::IoSlice::new(body)]) {
        Ok(IoStatus::Ready(n)) => n,
        Ok(IoStatus::WouldBlock) => 0,
        Err(e) => {
            log::debug!("dial: send to peer failed: {e}");
            return Outcome::Close;
        }
    };
    if sent > 0 {
        // Real forward progress: hold off the idle timeout.
        *deadline = Instant::now() + IDLE_TIMEOUT;
    }
    if sent == total {
        return Outcome::Keep;
    }
    let (header_tail, body_tail) = split_remainder(header, body, sent);
    buffer_tail(to_send, header_tail, body_tail)
}

/// Append the unsent `header`/`body` remainder to `to_send`; `Close` if it overflows the cap.
fn buffer_tail(to_send: &mut StreamBuffer, header: &[u8], body: &[u8]) -> Outcome {
    if to_send.append(header).is_err() || to_send.append(body).is_err() {
        log::warn!("dial: send buffer overflow; closing");
        return Outcome::Close;
    }
    Outcome::Keep
}

/// Split a `header`+`body` pair at the `sent` bytes already written front-to-back, giving the unsent
/// remainder of each. A single `writev` count can land inside either slice.
fn split_remainder<'a>(header: &'a [u8], body: &'a [u8], sent: usize) -> (&'a [u8], &'a [u8]) {
    if sent >= header.len() {
        (&[], &body[sent - header.len()..])
    } else {
        (&header[sent..], body)
    }
}

#[cfg(test)]
mod tests;
