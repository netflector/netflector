//! The DIAL application proxy: one per device, a reactor [`Handler`] that fronts the device's HTTP
//! endpoints on the source subnet. It accepts a client on its description listener, opens an
//! egress-pinned connection to the device on the target subnet, and splices the two — rewriting
//! authorities so the device's address never leaks to the client.
//!
//! This module is the connection lifecycle + dispatch skeleton: accept, connect, register, the
//! connect/idle deadlines, teardown, and self-eviction. The byte-splice data path (`forward`/`drain`
//! + the authority rewrites) and the lazily-minted REST listener follow in the next step.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::net::http::framing::{HttpFraming, Kind};
use crate::net::stream_buffer::StreamBuffer;
use crate::net::tcp::TcpSocket;
use crate::reactor::{Arena, Handler, HandlerKey, Key, Reactor, ReadyEvent, RegKey};

/// Per-connection, per-direction receive buffer: one read chunk plus header accumulation.
const MAX_RECV: usize = 4 * 1024;
/// Per-connection, per-direction send buffer: the unsent tail held under backpressure; past it the
/// connection drops-and-closes.
const MAX_SEND: usize = 8 * 1024;
/// Cap on concurrent proxied connections (drop-new past it).
const MAX_CONNECTIONS: usize = 64;
/// A non-blocking device connect must complete within this.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// An open connection idle this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The receive buffer must exceed the framer's header cap, or the over-cap refusal can't fire before
/// the buffer fills and the always-armed reader livelocks.
const _: () = assert!(MAX_RECV > crate::net::http::framing::MAX_HEADER);

/// One direction of the duplex splice: its HTTP framer, the recv buffer (bytes read from the source
/// side), and the send buffer (the unsent tail to the destination side under backpressure).
struct Flow {
    framer: HttpFraming,
    recv: StreamBuffer,
    send: StreamBuffer,
}

impl Flow {
    fn new(kind: Kind) -> Self {
        Self {
            framer: HttpFraming::new(kind),
            recv: StreamBuffer::with_capacity(MAX_RECV),
            send: StreamBuffer::with_capacity(MAX_SEND),
        }
    }
}

/// A `Copy` handle into the proxy's connection [`Arena`] — a newtype over the arena [`Key`] so it
/// can't be confused with the reactor's keys. It is the unit that round-trips through a watched fd's
/// `user_data`: the reactor echoes it back on every event, and dispatch decodes it to find the flow.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ConnectionKey(Key);

impl ConnectionKey {
    /// Pack into a watch's `user_data`.
    fn to_u64(self) -> u64 {
        self.0.to_u64()
    }

    /// Unpack from a dispatched event's `user_data`.
    fn from_u64(packed: u64) -> Self {
        Self(Key::from_u64(packed))
    }
}

/// One proxied client↔device connection. Each socket is watched under its own reg; `device_endpoint`
/// is where `device` connects and the `Host` rewrite target. `deadline` is the connect timeout while
/// the device connect is in flight, then the idle timeout. The regs are `None` only between insert and
/// watch in [`start_connection`](DialDeviceProxy::start_connection); every event sees them set.
struct Connection {
    client: TcpSocket,
    client_reg: Option<RegKey>,
    device: TcpSocket,
    device_reg: Option<RegKey>,
    device_endpoint: SocketAddrV4,
    c2u: Flow, // client -> device
    u2c: Flow, // device -> client
    deadline: Instant,
}

/// A per-device DIAL proxy — a reactor `Handler` owning a description listener and its connections.
pub(crate) struct DialDeviceProxy {
    /// This handler's own key, learned via [`adopt_key`](Handler::adopt_key); used to watch fds it
    /// opens and to self-unregister.
    key: Option<HandlerKey>,
    /// The source-interface address the description (and REST) listener binds — clients reach the
    /// proxy here.
    source: Ipv4Addr,
    /// The target-interface address device connections bind, so the device sees a same-segment peer
    /// and replies via the target interface (on the BSDs the bind is the only egress steer).
    target: Ipv4Addr,
    /// The target interface index, egress-pinning device connections to that segment.
    target_ifindex: u32,
    /// The description listener (source side); its connections proxy to `desc_device`.
    desc: TcpSocket,
    /// The device's description endpoint (`device-ip:desc_port`) — the proxy's identity.
    desc_device: SocketAddrV4,
    /// The instant the description listener may be reaped after, once idle — the advertisement's
    /// `max-age`, refreshed on re-advertisement.
    desc_grace: Instant,
    conns: Arena<Connection>,
}

impl DialDeviceProxy {
    /// A proxy fronting `desc_device` via the source-side `desc` listener. Device connections bind the
    /// target-interface `target` and egress-pin `target_ifindex`; `desc_grace` is when the listener may
    /// be reaped after once idle.
    pub(crate) fn new(
        source: Ipv4Addr,
        target: Ipv4Addr,
        target_ifindex: u32,
        desc: TcpSocket,
        desc_device: SocketAddrV4,
        desc_grace: Instant,
    ) -> Self {
        Self {
            key: None,
            source,
            target,
            target_ifindex,
            desc,
            desc_device,
            desc_grace,
            conns: Arena::new(),
        }
    }

    /// This handler's own key. `adopt_key` sets it at registration — before the reactor dispatches any
    /// event — so every method that runs has it; its absence would be a reactor-contract violation.
    fn own_key(&self) -> HandlerKey {
        self.key
            .expect("adopt_key sets the proxy's key before any dispatch")
    }

    /// Accept one pending client on the description listener and start its proxied connection. The
    /// listener is non-blocking, so a level-triggered wait re-fires while more wait; an accept is
    /// always taken (draining the readiness) even at the connection cap, where the client is dropped.
    fn accept(&mut self, reactor: &mut Reactor) {
        let client = match self.desc.accept() {
            Ok(Some(client)) => client,
            Ok(None) => return, // spurious / already taken
            Err(e) => {
                log::warn!("dial: accept on the description listener failed: {e}");
                return;
            }
        };
        if self.conns.iter().count() >= MAX_CONNECTIONS {
            log::warn!("dial: connection cap ({MAX_CONNECTIONS}) reached; dropping a new client");
            return; // `client` drops here, closing it
        }
        let device = self.desc_device;
        self.start_connection(client, device, reactor);
    }

    /// Open an egress-pinned connection to `device_endpoint`, register both fds, and record the
    /// connection. Best-effort: a connect or watch failure drops the half-built connection.
    fn start_connection(
        &mut self,
        client: TcpSocket,
        device_endpoint: SocketAddrV4,
        reactor: &mut Reactor,
    ) {
        let key = self.own_key();
        let device = match TcpSocket::connect(device_endpoint, self.target, self.target_ifindex) {
            Ok(device) => device,
            Err(e) => {
                log::warn!("dial: connect to {device_endpoint} failed: {e}");
                return;
            }
        };
        let client_fd = client.as_raw_fd();
        let device_fd = device.as_raw_fd();
        // Insert first so the connection's arena key can tag both fds' `user_data`; the regs are
        // patched in once watching succeeds.
        let conn_key = ConnectionKey(self.conns.insert(Connection {
            client,
            client_reg: None,
            device,
            device_reg: None,
            device_endpoint,
            c2u: Flow::new(Kind::Request),
            u2c: Flow::new(Kind::Response),
            deadline: Instant::now() + CONNECT_TIMEOUT,
        }));
        let user_data = conn_key.to_u64();
        let client_reg = match reactor.watch(key, client_fd, user_data) {
            Ok(reg) => reg,
            Err(e) => {
                log::warn!("dial: watching the client fd failed: {e}");
                self.close_conn(conn_key, reactor);
                return;
            }
        };
        let device_reg = match reactor.watch(key, device_fd, user_data) {
            Ok(reg) => reg,
            Err(e) => {
                log::warn!("dial: watching the device fd failed: {e}");
                reactor.unwatch(client_reg).ok();
                self.close_conn(conn_key, reactor);
                return;
            }
        };
        // Arm the device's write interest so its connect completion (a writable edge) is delivered.
        reactor.set_write_interest(device_reg, true).ok();
        let conn = self
            .conns
            .get_mut(conn_key.0)
            .expect("the just-inserted connection is present");
        conn.client_reg = Some(client_reg);
        conn.device_reg = Some(device_reg);
        log::debug!("dial: accepted a client; connecting to {device_endpoint}");
    }

    /// A connection socket is writable. While the device connect is in flight this completes it;
    /// draining the send buffer under backpressure lands in the next step.
    fn on_connection_writable(
        &mut self,
        conn_key: ConnectionKey,
        fd: RawFd,
        reactor: &mut Reactor,
    ) {
        let close = {
            let Some(conn) = self.conns.get_mut(conn_key.0) else {
                // The reactor filters stale registrations, so a live write event should map to a live
                // connection; a miss means the generational key out-lived its slot — fail safe.
                log::trace!("dial: writable event for an unknown connection; ignoring");
                return;
            };
            if conn.device.as_raw_fd() == fd && conn.device.is_connecting() {
                match conn.device.finish_connect() {
                    Ok(()) => {
                        conn.deadline = Instant::now() + IDLE_TIMEOUT;
                        // Disarm the device's write interest until backpressure needs it again. A
                        // persisted connection is fully built, so its registration is set.
                        let reg = conn
                            .device_reg
                            .expect("a persisted connection has its device registration set");
                        reactor.set_write_interest(reg, false).ok();
                        false
                    }
                    Err(e) => {
                        log::warn!(
                            "dial: device connect to {} failed: {e}",
                            conn.device_endpoint
                        );
                        true
                    }
                }
            } else {
                false // 6c-ii: drain the send buffer for this direction
            }
        };
        if close {
            self.close_conn(conn_key, reactor);
        }
    }

    /// Tear down the connection `conn_key` addresses: drop each watched fd's kernel interest, then
    /// shut both sockets down. Every caller holds a live key (just inserted, just matched, or from a
    /// live sweep), so the connection is present; a half-built one may have no registrations yet.
    fn close_conn(&mut self, conn_key: ConnectionKey, reactor: &mut Reactor) {
        let conn = self
            .conns
            .remove(conn_key.0)
            .expect("close_conn's callers hold a live connection key");
        if let Some(reg) = conn.client_reg {
            reactor.unwatch(reg).ok();
        }
        if let Some(reg) = conn.device_reg {
            reactor.unwatch(reg).ok();
        }
        conn.client.shutdown();
        conn.device.shutdown();
        log::debug!("dial: closed a connection to {}", conn.device_endpoint);
    }

    /// Close connections past their deadline (connect timeout or idle), then self-unregister once
    /// idle past the description grace — the device's advertised validity has lapsed with no traffic.
    fn sweep(&mut self, now: Instant, reactor: &mut Reactor) {
        let expired: Vec<(ConnectionKey, SocketAddrV4)> = self
            .conns
            .iter()
            .filter(|(_, conn)| now >= conn.deadline)
            .map(|(key, conn)| (ConnectionKey(key), conn.device_endpoint))
            .collect();
        for (conn_key, device_endpoint) in expired {
            log::debug!("dial: connection to {device_endpoint} timed out");
            self.close_conn(conn_key, reactor);
        }
        if self.conns.iter().next().is_none() && now >= self.desc_grace {
            log::debug!("dial: idle past its grace; evicting the proxy");
            reactor.unregister(self.own_key()).ok();
        }
    }
}

impl Handler for DialDeviceProxy {
    fn adopt_key(&mut self, key: HandlerKey) {
        self.key = Some(key);
    }

    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        // Connection-socket readability (the byte splice) lands in the next step; until then only the
        // description listener's readiness is acted on here.
        if event.fd == self.desc.as_raw_fd() {
            self.accept(reactor);
        }
    }

    fn on_writable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        // Listeners never arm write interest, so a writable edge is always a connection socket.
        self.on_connection_writable(ConnectionKey::from_u64(event.user_data), event.fd, reactor);
    }

    fn next_deadline(&self) -> Option<Instant> {
        // While connections are live, wake at the soonest; otherwise wake at the description grace to
        // self-reap once the device's advertised validity has lapsed.
        self.conns
            .iter()
            .map(|(_, conn)| conn.deadline)
            .min()
            .or(Some(self.desc_grace))
    }

    fn on_deadline(&mut self, now: Instant, reactor: &mut Reactor) {
        self.sweep(now, reactor);
    }
}
