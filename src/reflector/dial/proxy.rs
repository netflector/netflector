//! The per-device DIAL proxy: a reactor [`Handler`] fronting one device's HTTP endpoints.
//!
//! [`DialDeviceProxy`] owns a description listener, a REST listener and a pool of live
//! [`Connection`]s. Its own eviction belongs to the [`DialContext`](crate::dispatch::DialContext)
//! registry; it only sweeps its connections past their connect/idle deadlines.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::logging::log_rate;
use crate::net::is_never_a_peer;
use crate::net::tcp::TcpSocket;
use crate::reactor::{Arena, Handler, HandlerKey, Key, Reactor, ReadyEvent};

use super::connection::{Connection, Outcome};
use super::egress;

/// Past it, new clients are dropped.
const MAX_CONNECTIONS: usize = 64;

/// A source-side host can reach the cap on its own, so a line per rejected client would hand it
/// the log.
const CAP_WARN_INTERVAL: Duration = Duration::from_mins(1);

/// A handle into the proxy's connection [`Arena`]. Round-trips through a watched fd's `user_data`:
/// the reactor echoes it back on every event.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ConnectionKey(Key);

impl ConnectionKey {
    fn to_u64(self) -> u64 {
        self.0.to_u64()
    }

    fn from_u64(packed: u64) -> Self {
        Self(Key::from_u64(packed))
    }
}

#[derive(Clone, Copy)]
pub(super) enum Listener {
    Description,
    Rest,
}

impl fmt::Display for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Description => "description",
            Self::Rest => "REST",
        })
    }
}

pub(super) struct DialDeviceProxy {
    /// Set by [`adopt_key`](Handler::adopt_key) at registration.
    key: Option<HandlerKey>,
    /// The target-interface address device connections bind, so the device sees a same-segment
    /// peer. The bind picks the source address only; `target_iface` keeps the connection on that
    /// segment.
    target: Ipv4Addr,
    /// The name, not an ifindex: it stays valid across an interface recreation. `None` skips the
    /// confinement.
    target_iface: Option<String>,
    desc: TcpSocket,
    desc_endpoint: SocketAddrV4,
    /// Minted eagerly so its address exists to rewrite a description response's `Application-URL`
    /// to.
    rest: TcpSocket,
    /// Learned from a description response's `Application-URL`; `None` until the first fetch.
    rest_endpoint: Option<SocketAddrV4>,
    conns: Arena<Connection>,
}

impl DialDeviceProxy {
    pub(super) fn new(
        target: Ipv4Addr,
        target_iface: Option<String>,
        desc: TcpSocket,
        desc_endpoint: SocketAddrV4,
        rest: TcpSocket,
    ) -> Self {
        Self {
            key: None,
            target,
            target_iface,
            desc,
            desc_endpoint,
            rest,
            rest_endpoint: None,
            conns: Arena::new(),
        }
    }

    fn own_key(&self) -> HandlerKey {
        self.key
            .expect("adopt_key sets the proxy's key before any dispatch")
    }

    /// Always accepts, draining the readiness, and drops the client at the connection cap. A failed
    /// accept sheds the whole proxy: under `EMFILE` the connection stays queued and this
    /// level-triggered listener would re-fire on it without end. The device re-mints on its next
    /// advertisement.
    fn accept_client(&mut self, what: Listener, reactor: &mut Reactor) -> Option<TcpSocket> {
        let listener = match what {
            Listener::Description => &self.desc,
            Listener::Rest => &self.rest,
        };
        let client = match listener.accept() {
            Ok(Some(client)) => client,
            Ok(None) => return None,
            Err(e) => {
                log::error!(
                    "dial: accept on the {what} listener failed: {e}; tearing the proxy down, \
                     {} is unproxied until it advertises again",
                    self.desc_endpoint
                );
                reactor.unregister(self.own_key()).ok();
                return None;
            }
        };
        if self.conns.iter().count() >= MAX_CONNECTIONS {
            log_rate!(
                log::Level::Warn,
                CAP_WARN_INTERVAL,
                "dial: connection cap ({MAX_CONNECTIONS}) reached for {}; dropping new clients",
                self.desc_endpoint
            );
            return None;
        }
        Some(client)
    }

    fn accept_desc(&mut self, reactor: &mut Reactor) {
        if let Some(client) = self.accept_client(Listener::Description, reactor) {
            self.start_connection(client, self.desc_endpoint, self.desc.local_addr(), reactor);
        }
    }

    /// A client before the REST endpoint is learned is unexpected: only a description response the
    /// proxy rewrote names this listener.
    fn accept_rest(&mut self, reactor: &mut Reactor) {
        let Some(client) = self.accept_client(Listener::Rest, reactor) else {
            return;
        };
        let Some(device) = self.rest_endpoint else {
            log::warn!(
                "dial: REST request before the device's REST endpoint is known; dropping it"
            );
            return;
        };
        self.start_connection(client, device, self.rest.local_addr(), reactor);
    }

    fn start_connection(
        &mut self,
        client: TcpSocket,
        device_endpoint: SocketAddrV4,
        own_listener: SocketAddrV4,
        reactor: &mut Reactor,
    ) {
        let key = self.own_key();
        let rest_listener = self.rest.local_addr();
        let confine = |fd| egress::confine(fd, device_endpoint, self.target_iface.as_deref());
        let device = match TcpSocket::connect(device_endpoint, self.target, confine) {
            Ok(device) => device,
            Err(e) => {
                log::warn!("dial: connect to {device_endpoint} failed: {e}");
                return;
            }
        };
        let client_fd = client.as_raw_fd();
        let device_fd = device.as_raw_fd();
        // Insert first: the arena key tags both fds' `user_data`.
        let conn_key = ConnectionKey(self.conns.insert(Connection::new(
            client,
            device,
            device_endpoint,
            rest_listener,
            own_listener,
        )));
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
        conn.attach_registrations(client_reg, device_reg);
        log::debug!("dial: accepted a client; connecting to {device_endpoint}");
    }

    fn on_connection_readable(
        &mut self,
        conn_key: ConnectionKey,
        fd: RawFd,
        reactor: &mut Reactor,
    ) {
        let (outcome, learned) = {
            let Some(conn) = self.conns.get_mut(conn_key.0) else {
                log::trace!("dial: readable event for an unknown connection; ignoring");
                return;
            };
            let outcome = conn.readable(fd, reactor);
            (outcome, conn.take_learned_rest())
        };
        if let Some(endpoint) = learned {
            self.adopt_rest_endpoint(endpoint);
        }
        if outcome == Outcome::Close {
            self.close_conn(conn_key, reactor);
        }
    }

    /// Refuses an endpoint that can never name a device ([`is_never_a_peer`]): dialing it would reach
    /// a local service. Link-local is fine on purpose: the dial goes out the target interface,
    /// on-link.
    fn adopt_rest_endpoint(&mut self, endpoint: SocketAddrV4) {
        if is_never_a_peer(IpAddr::V4(*endpoint.ip())) {
            log::debug!(
                "dial: ignoring {}'s REST endpoint {endpoint}: it can never name a device",
                self.desc_endpoint
            );
            return;
        }
        if self.rest_endpoint != Some(endpoint) {
            log::debug!(
                "dial: learned {}'s REST endpoint {endpoint}",
                self.desc_endpoint
            );
        }
        self.rest_endpoint = Some(endpoint);
    }

    fn on_connection_writable(
        &mut self,
        conn_key: ConnectionKey,
        fd: RawFd,
        reactor: &mut Reactor,
    ) {
        let outcome = {
            let Some(conn) = self.conns.get_mut(conn_key.0) else {
                log::trace!("dial: writable event for an unknown connection; ignoring");
                return;
            };
            conn.writable(fd, reactor)
        };
        if outcome == Outcome::Close {
            self.close_conn(conn_key, reactor);
        }
    }

    fn close_conn(&mut self, conn_key: ConnectionKey, reactor: &mut Reactor) {
        let conn = self
            .conns
            .remove(conn_key.0)
            .expect("close_conn's callers hold a live connection key");
        let endpoint = conn.device_endpoint();
        conn.teardown(reactor);
        log::debug!("dial: closed a connection to {endpoint}");
    }

    fn sweep(&mut self, now: Instant, reactor: &mut Reactor) {
        let expired: Vec<(ConnectionKey, SocketAddrV4)> = self
            .conns
            .iter()
            .filter(|(_, conn)| now >= conn.deadline())
            .map(|(key, conn)| (ConnectionKey(key), conn.device_endpoint()))
            .collect();
        for (conn_key, device_endpoint) in expired {
            log::debug!("dial: connection to {device_endpoint} timed out");
            self.close_conn(conn_key, reactor);
        }
    }
}

impl Handler for DialDeviceProxy {
    fn adopt_key(&mut self, key: HandlerKey) {
        self.key = Some(key);
    }

    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        if event.fd == self.desc.as_raw_fd() {
            self.accept_desc(reactor);
        } else if event.fd == self.rest.as_raw_fd() {
            self.accept_rest(reactor);
        } else {
            self.on_connection_readable(
                ConnectionKey::from_u64(event.user_data),
                event.fd,
                reactor,
            );
        }
    }

    fn on_writable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        // Listeners never arm write interest, so a writable edge is always a connection socket.
        self.on_connection_writable(ConnectionKey::from_u64(event.user_data), event.fd, reactor);
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.conns.iter().map(|(_, conn)| conn.deadline()).min()
    }

    fn on_deadline(&mut self, now: Instant, reactor: &mut Reactor) {
        self.sweep(now, reactor);
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;
    use crate::sys::IoStatus;
    use crate::test_support::NoopHandler;

    /// A proxy with bound loopback desc/rest listeners, its key borrowed from a placeholder handler so
    /// `start_connection`'s watches resolve without dispatching through the reactor. Returns the proxy and
    /// its REST listener address (a client connects there to reach `accept_rest`); `rest_endpoint` starts
    /// unlearned.
    fn watched_proxy(reactor: &mut Reactor) -> (DialDeviceProxy, SocketAddrV4) {
        let key = reactor.register(Box::new(NoopHandler));
        let desc = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("desc listen");
        let rest = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("rest listen");
        let rest_addr = rest.local_addr();
        let mut proxy = DialDeviceProxy::new(
            Ipv4Addr::LOCALHOST,
            None, // no egress pin on loopback
            desc,
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 8008),
            rest,
        );
        proxy.adopt_key(key);
        (proxy, rest_addr)
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real poll backend")]
    fn a_never_a_peer_rest_endpoint_is_not_adopted() {
        let mut reactor = Reactor::new().expect("reactor");
        let (mut proxy, _rest_addr) = watched_proxy(&mut reactor);
        let device: SocketAddrV4 = "10.0.0.5:8009".parse().unwrap();
        proxy.adopt_rest_endpoint(device);
        assert_eq!(proxy.rest_endpoint, Some(device));
        // A later description naming loopback or unspecified does not displace it.
        proxy.adopt_rest_endpoint("127.0.0.1:9".parse().unwrap());
        proxy.adopt_rest_endpoint("0.0.0.0:8009".parse().unwrap());
        assert_eq!(proxy.rest_endpoint, Some(device));
        // A link-local endpoint is adoptable: the proxy dials it on-link from the target side.
        let link_local: SocketAddrV4 = "169.254.9.9:8009".parse().unwrap();
        proxy.adopt_rest_endpoint(link_local);
        assert_eq!(proxy.rest_endpoint, Some(link_local));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real poll backend")]
    fn accept_rest_proxies_to_the_learned_rest_endpoint() {
        let mut reactor = Reactor::new().expect("reactor");
        let (mut proxy, rest_addr) = watched_proxy(&mut reactor);
        // A loopback stand-in for the device's REST endpoint a prior description fetch revealed.
        let device = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("device REST listen");
        let device_endpoint = device.local_addr();
        proxy.rest_endpoint = Some(device_endpoint);

        // A client reaches the REST listener; drive accept until the loopback handshake lands.
        let _client =
            TcpSocket::connect(rest_addr, Ipv4Addr::LOCALHOST, |_| Ok(())).expect("client connect");
        for _ in 0..2000 {
            proxy.accept_rest(&mut reactor);
            if proxy.conns.iter().count() == 1 {
                break;
            }
            sleep(Duration::from_millis(1));
        }

        let (_, conn) = proxy
            .conns
            .iter()
            .next()
            .expect("a REST connection was started");
        assert_eq!(
            conn.device_endpoint(),
            device_endpoint,
            "the REST connection targets the learned REST endpoint, not the description endpoint"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real poll backend")]
    fn a_failed_accept_sheds_the_proxy() {
        let mut reactor = Reactor::new().expect("reactor");
        let (mut proxy, rest_addr) = watched_proxy(&mut reactor);
        let key = proxy.own_key();
        assert!(reactor.is_registered(key));

        // Accepting on a connected socket fails with EINVAL, standing in for the EMFILE the proxy
        // cannot drain. Either way it must not stay registered and re-firing on a readiness it
        // will never consume.
        proxy.rest =
            TcpSocket::connect(rest_addr, Ipv4Addr::LOCALHOST, |_| Ok(())).expect("client connect");
        assert!(proxy.accept_client(Listener::Rest, &mut reactor).is_none());
        assert!(
            !reactor.is_registered(key),
            "the proxy unregisters itself rather than spin on a listener it cannot drain"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real poll backend")]
    fn accept_rest_drops_a_client_before_the_rest_endpoint_is_learned() {
        let mut reactor = Reactor::new().expect("reactor");
        let (mut proxy, rest_addr) = watched_proxy(&mut reactor); // rest_endpoint stays None
        let client =
            TcpSocket::connect(rest_addr, Ipv4Addr::LOCALHOST, |_| Ok(())).expect("client connect");

        // accept_rest accepts the client (draining the listener) but, with no learned endpoint, drops
        // it. The client observes EOF and no connection is recorded.
        let mut buf = [0u8; 1];
        let mut closed = false;
        for _ in 0..2000 {
            proxy.accept_rest(&mut reactor);
            if matches!(client.recv(&mut buf), Ok(IoStatus::Ready(0))) {
                closed = true;
                break;
            }
            sleep(Duration::from_millis(1));
        }
        assert!(
            closed,
            "the proxy accepted then closed the unservable REST client"
        );
        assert_eq!(
            proxy.conns.iter().count(),
            0,
            "no connection is started before the REST endpoint is known"
        );
    }
}
