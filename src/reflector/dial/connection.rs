//! One proxied client↔device connection: the bidirectional HTTP byte splice.
//!
//! Each [`Connection`] pairs two sockets with a per-direction [`Flow`], driven on the reactor's
//! readable/writable edges: a readable edge frames whole messages out of the source, rewrites their
//! authority headers and forwards them; a writable edge drains the backlog. Each direction
//! half-closes independently. Backpressure is drop-and-close: a send-buffer overflow tears the
//! connection down rather than throttling the reader.

use std::io;
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::net::http::framing::{HttpFraming, Kind, RewritePolicy};
use crate::net::stream_buffer::StreamBuffer;
use crate::net::tcp::TcpSocket;
use crate::reactor::{Reactor, RegKey};
use crate::sys::IoStatus;

const MAX_RECV: usize = 4 * 1024;
const MAX_SEND: usize = 8 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Must exceed the framer's header cap, or the over-cap refusal can't fire before the buffer fills and
/// the always-armed reader livelocks.
const _: () = assert!(MAX_RECV > crate::net::http::framing::MAX_HEADER);

/// A direction's half-close progress: `SourceClosed` while the source's EOF is still flushing
/// toward the destination, `Done` once it's flushed and the destination's write is shut.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FlowState {
    Open,
    SourceClosed,
    Done,
}

/// One direction of the splice.
struct Flow {
    framer: HttpFraming,
    recv: StreamBuffer,
    send: StreamBuffer,
    state: FlowState,
}

impl Flow {
    fn new(kind: Kind, rewrite: RewritePolicy) -> Self {
        Self {
            framer: HttpFraming::new(kind, rewrite),
            recv: StreamBuffer::with_capacity(MAX_RECV),
            send: StreamBuffer::with_capacity(MAX_SEND),
            state: FlowState::Open,
        }
    }
}

/// `ClientToDevice` is the `c2u` flow, `DeviceToClient` the `u2c`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToDevice,
    DeviceToClient,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Outcome {
    Keep,
    Close,
}

enum Forwarded {
    Open,
    SourceEof,
    Failed,
}

/// One `Direction` resolved against a connection, built once per event so the forward/drain paths
/// never re-pick a side.
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
    /// Read one chunk, frame whole messages out of it, rewrite and forward them, buffering any
    /// unsent tail for the writable edge. The deadline moves only when bytes reach the destination,
    /// so a wedged connection still ages out.
    fn forward(&mut self) -> Forwarded {
        let tail = self.flow.recv.free_tail_mut();
        if tail.is_empty() {
            log::warn!("dial: receive buffer full of an unframable message; closing");
            return Forwarded::Failed;
        }
        let n = match self.from.recv(tail) {
            Ok(IoStatus::Ready(0)) => return Forwarded::SourceEof,
            Ok(IoStatus::Ready(n)) => n,
            Ok(IoStatus::WouldBlock) => return Forwarded::Open,
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
            // Only the response framer reports an Application-URL, so this can't fire on the
            // client→device side; the latest message wins.
            if let Some(ep) = framed.application_url {
                *self.learned_rest = Some(ep);
            }
            if framed.consumed == 0 {
                break;
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

    /// Disarm the half-closed source's read interest: its FIN is permanently readable and would
    /// re-fire every wait. The destination stays open, so the reverse direction keeps flowing.
    fn half_close(&mut self, reactor: &mut Reactor) -> Outcome {
        // Only an Open flow reaches here, and peer_gone marks a flow Done before taking its reg.
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

    /// After a forward or drain: FIN the destination once a closed source's backlog is flushed,
    /// then sync the write interest. A drained flow disarms it, so `on_writable` never re-enters
    /// and the FIN fires exactly once.
    fn settle(&mut self, reactor: &mut Reactor) -> Outcome {
        // While the destination is still connecting, `shutdown_write` would be an ENOTCONN no-op
        // and the FIN lost; the connect-completion edge (kept armed below) leads to a later settle.
        if self.flow.state == FlowState::SourceClosed
            && self.flow.send.is_empty()
            && !self.to.is_connecting()
        {
            self.to.shutdown_write();
            self.flow.state = FlowState::Done;
        }
        self.sync_write_interest(reactor)
    }

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

    /// Armed while a backlog remains or the destination is still connecting, so the
    /// connect-completion edge (a writable edge with no backlog) survives. A rejected change is
    /// `Close`: the buffered send would otherwise strand with no re-arm.
    fn sync_write_interest(&self, reactor: &mut Reactor) -> Outcome {
        let armed = !self.flow.send.is_empty() || self.to.is_connecting();
        // As in half_close: no peer_gone has taken this direction's destination reg.
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

/// One proxied client↔device connection. A reg is `None` before
/// [`attach_registrations`](Self::attach_registrations) and again once
/// [`peer_gone`](Self::peer_gone) takes the hung-up side's; [`forward`](Self::forward) reads that
/// `None` as "both peers gone".
pub(super) struct Connection {
    client: TcpSocket,
    client_reg: Option<RegKey>,
    device: TcpSocket,
    device_reg: Option<RegKey>,
    device_endpoint: SocketAddrV4,
    c2u: Flow, // client -> device
    u2c: Flow, // device -> client
    /// Lifted into the proxy's `rest_endpoint` after each readable edge.
    learned_rest: Option<SocketAddrV4>,
    deadline: Instant,
}

impl Connection {
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

    pub(super) fn attach_registrations(&mut self, client_reg: RegKey, device_reg: RegKey) {
        self.client_reg = Some(client_reg);
        self.device_reg = Some(device_reg);
    }

    pub(super) fn device_endpoint(&self) -> SocketAddrV4 {
        self.device_endpoint
    }

    /// The connect timeout, then the idle timeout.
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(super) fn take_learned_rest(&mut self) -> Option<SocketAddrV4> {
        self.learned_rest.take()
    }

    pub(super) fn readable(&mut self, fd: RawFd, reactor: &mut Reactor) -> Outcome {
        let direction = if self.client.as_raw_fd() == fd {
            Direction::ClientToDevice
        } else {
            Direction::DeviceToClient
        };
        self.forward(direction, reactor)
    }

    pub(super) fn writable(&mut self, fd: RawFd, reactor: &mut Reactor) -> Outcome {
        let direction = if self.device.as_raw_fd() == fd {
            Direction::ClientToDevice
        } else {
            Direction::DeviceToClient
        };
        self.on_writable(direction, reactor)
    }

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

    fn close_if_complete(&self, outcome: Outcome) -> Outcome {
        if outcome == Outcome::Close
            || (self.c2u.state == FlowState::Done && self.u2c.state == FlowState::Done)
        {
            Outcome::Close
        } else {
            Outcome::Keep
        }
    }

    /// `direction`'s source peer hung up. Its buffered bytes still drain toward the live peer (then
    /// FIN); the reverse direction is abandoned as `Done` and its source read disarmed, lest a
    /// stray edge re-enter. The vanished fd is unwatched: its level-triggered HUP would re-fire
    /// every wait.
    fn peer_gone(&mut self, direction: Direction, reactor: &mut Reactor) -> Outcome {
        log::debug!(
            "dial: {} hung up on the connection to {}",
            match direction {
                Direction::ClientToDevice => "client",
                Direction::DeviceToClient => "device",
            },
            self.device_endpoint
        );
        // forward routes here only with a live destination reg, and peer_gone runs once per side,
        // so both expects hold.
        let (disarm_reg, unwatch_reg) = match direction {
            Direction::ClientToDevice => {
                self.u2c.state = FlowState::Done;
                (
                    self.device_reg
                        .expect("a live destination keeps its registration"),
                    self.client_reg
                        .take()
                        .expect("the hung-up source still has its registration"),
                )
            }
            Direction::DeviceToClient => {
                self.c2u.state = FlowState::Done;
                (
                    self.client_reg
                        .expect("a live destination keeps its registration"),
                    self.device_reg
                        .take()
                        .expect("the hung-up source still has its registration"),
                )
            }
        };
        // Not `.ok()`: a still-watched hung-up fd would re-fire its HUP, re-enter here and find its
        // reg taken.
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

    fn forward(&mut self, direction: Direction, reactor: &mut Reactor) -> Outcome {
        let mut ctx = self.context(direction);
        // A non-Open flow's read was disarmed, so only a hangup/reset wakes it: epoll delivers
        // HUP/ERR regardless of the read mask. A `None` destination reg means a prior peer_gone took
        // it, so both peers are gone.
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

/// A backlog or a pending connect buffers the whole message, to preserve order; otherwise one
/// scatter-gather write, and only the unsent tail is buffered.
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
        *deadline = Instant::now() + IDLE_TIMEOUT;
    }
    if sent == total {
        return Outcome::Keep;
    }
    let (header_tail, body_tail) = split_remainder(header, body, sent);
    buffer_tail(to_send, header_tail, body_tail)
}

fn buffer_tail(to_send: &mut StreamBuffer, header: &[u8], body: &[u8]) -> Outcome {
    if to_send.append(header).is_err() || to_send.append(body).is_err() {
        log::warn!("dial: send buffer overflow; closing");
        return Outcome::Close;
    }
    Outcome::Keep
}

/// A `writev` count can land inside either slice.
fn split_remainder<'a>(header: &'a [u8], body: &'a [u8], sent: usize) -> (&'a [u8], &'a [u8]) {
    if sent >= header.len() {
        (&[], &body[sent - header.len()..])
    } else {
        (&header[sent..], body)
    }
}

#[cfg(test)]
mod tests;
