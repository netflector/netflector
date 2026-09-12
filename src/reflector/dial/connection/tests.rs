use std::thread::sleep;

use super::*;
use crate::test_support::NoopHandler;

/// Drive a non-blocking op to completion on loopback (no reactor in the test).
fn spin<T>(mut op: impl FnMut() -> io::Result<Option<T>>) -> T {
    for _ in 0..2000 {
        if let Some(value) = op().expect("operation errored") {
            return value;
        }
        sleep(Duration::from_millis(1));
    }
    panic!("operation did not complete on loopback within the timeout");
}

/// A connected loopback TCP pair: `(initiator, accepted)`.
fn connected_pair() -> (TcpSocket, TcpSocket) {
    let listener = TcpSocket::listen(std::net::Ipv4Addr::LOCALHOST).expect("listen on loopback");
    let mut initiator =
        TcpSocket::connect(listener.local_addr(), std::net::Ipv4Addr::LOCALHOST, None)
            .expect("connect");
    let accepted = spin(|| listener.accept());
    initiator.finish_connect().expect("the connect completed");
    (initiator, accepted)
}

/// Drive `forward_dir` until the message it forwards arrives at `peer_out`. Returns those bytes
/// alongside the REST endpoint learned from an `Application-URL`, if any.
fn drive_forward(
    from: &TcpSocket,
    to: &TcpSocket,
    flow: &mut Flow,
    peer_out: &TcpSocket,
) -> (Vec<u8>, Option<SocketAddrV4>) {
    let mut deadline = Instant::now();
    let mut learned_rest = None;
    let mut buf = [0u8; 1024];
    for _ in 0..2000 {
        {
            let mut ctx = DirectionContext {
                from,
                from_reg: None,
                to,
                to_reg: None,
                flow: &mut *flow,
                learned_rest: &mut learned_rest,
                deadline: &mut deadline,
            };
            assert!(
                matches!(ctx.forward(), Forwarded::Open),
                "forward should stay open on a clean message"
            );
        }
        match peer_out.recv_bytes(&mut buf).expect("recv on the peer") {
            IoStatus::Ready(0) => panic!("unexpected EOF before the forwarded bytes"),
            IoStatus::Ready(n) => return (buf[..n].to_vec(), learned_rest),
            IoStatus::WouldBlock => sleep(Duration::from_millis(1)),
        }
    }
    panic!("the forwarded bytes never arrived on loopback");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn split_remainder_when_the_header_is_fully_sent() {
    let (header, body) = split_remainder(b"head", b"body", 6); // 4 header + 2 body written
    assert_eq!(header, b"");
    assert_eq!(body, b"dy");
}

#[test]
fn split_remainder_when_the_header_is_partly_sent() {
    let (header, body) = split_remainder(b"head", b"body", 2);
    assert_eq!(header, b"ad");
    assert_eq!(body, b"body");
}

#[test]
fn buffer_tail_keeps_within_cap_and_closes_on_overflow() {
    let mut send = StreamBuffer::with_capacity(4);
    assert_eq!(buffer_tail(&mut send, b"ab", b"cd"), Outcome::Keep); // fills the 4-byte cap
    assert_eq!(buffer_tail(&mut send, b"x", b""), Outcome::Close); // past it: drop-and-close
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn forward_dir_frames_a_request_and_rewrites_host() {
    let (peer_in, from) = connected_pair(); // peer_in -> from (the client side)
    let (to, peer_out) = connected_pair(); // to -> peer_out (the device side)
    let device = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 5), 8008);
    assert!(matches!(
        peer_in
            .send(b"GET /apps HTTP/1.1\r\nHost: 192.168.1.2:80\r\n\r\n")
            .expect("send the request"),
        IoStatus::Ready(_)
    ));
    let rewrite = RewritePolicy {
        host: Some(device),
        application_url: None,
        location: None,
    };
    let mut flow = Flow::new(Kind::Request, rewrite);
    let (got, _) = drive_forward(&from, &to, &mut flow, &peer_out);
    assert!(
        got.starts_with(b"GET /apps HTTP/1.1\r\n"),
        "request line preserved: {:?}",
        String::from_utf8_lossy(&got)
    );
    assert!(
        contains(&got, b"Host: 10.0.0.5:8008\r\n"),
        "Host rewritten to the device: {:?}",
        String::from_utf8_lossy(&got)
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn forward_dir_rewrites_application_url_to_the_rest_listener_and_learns_it() {
    let (peer_in, from) = connected_pair();
    let (to, peer_out) = connected_pair();
    // The DD-connection u2c policy points Application-URL at the proxy's REST listener so the
    // device's REST endpoint never reaches the client; the proxy learns that endpoint instead.
    let rest_listener = SocketAddrV4::new(std::net::Ipv4Addr::new(192, 168, 1, 1), 9000);
    let rewrite = RewritePolicy {
        host: None,
        application_url: Some(rest_listener),
        location: None,
    };
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\
             Application-URL: http://192.168.1.2:8008/apps\r\n\r\nhello";
    assert!(matches!(
        peer_in
            .send(response.as_bytes())
            .expect("send the response"),
        IoStatus::Ready(_)
    ));
    let mut flow = Flow::new(Kind::Response, rewrite);
    let (got, learned) = drive_forward(&from, &to, &mut flow, &peer_out);
    assert!(
        contains(&got, b"Application-URL: http://192.168.1.1:9000/apps\r\n"),
        "Application-URL rewritten to the REST listener: {:?}",
        String::from_utf8_lossy(&got)
    );
    assert_eq!(
        learned,
        Some(SocketAddrV4::new(
            std::net::Ipv4Addr::new(192, 168, 1, 2),
            8008
        )),
        "the device's Application-URL endpoint is learned for the REST connection"
    );
    assert!(got.ends_with(b"hello"), "body forwarded: {got:?}");
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn forward_dir_never_learns_a_rest_endpoint_from_a_client_request() {
    let (peer_in, from) = connected_pair();
    let (to, peer_out) = connected_pair();
    // The client side must not be able to name the proxy's REST upstream: whatever is learned here
    // becomes the address every later REST client is spliced to, on the target segment. Pinned at
    // this layer too, since `learned_rest` is shared by both directions and only the framer's
    // `Kind` keeps the request side out of it.
    let device = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 5), 8008);
    let request = "GET /dd.xml HTTP/1.1\r\nHost: 192.168.1.2:80\r\n\
             Application-URL: http://192.168.9.9:22/\r\n\r\n";
    assert!(matches!(
        peer_in.send(request.as_bytes()).expect("send the request"),
        IoStatus::Ready(_)
    ));
    let rewrite = RewritePolicy {
        host: Some(device),
        application_url: None,
        location: None,
    };
    let mut flow = Flow::new(Kind::Request, rewrite);
    let (got, learned) = drive_forward(&from, &to, &mut flow, &peer_out);
    assert_eq!(learned, None, "a client cannot name the REST endpoint");
    assert!(
        contains(&got, b"Application-URL: http://192.168.9.9:22/\r\n"),
        "the unrecognized header still reaches the device verbatim: {:?}",
        String::from_utf8_lossy(&got)
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn forward_dir_rewrites_a_location_redirect_to_the_desc_listener() {
    let (peer_in, from) = connected_pair();
    let (to, peer_out) = connected_pair();
    // A rare dd redirect: Location points the client back at the proxy's own desc listener, not
    // the device. It is not a REST endpoint, so nothing is learned.
    let own_listener = SocketAddrV4::new(std::net::Ipv4Addr::new(192, 168, 1, 1), 1901);
    let rewrite = RewritePolicy {
        host: None,
        application_url: None,
        location: Some(own_listener),
    };
    let response = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\
             Location: http://192.168.1.2:8008/dd.xml\r\n\r\n";
    assert!(matches!(
        peer_in
            .send(response.as_bytes())
            .expect("send the response"),
        IoStatus::Ready(_)
    ));
    let mut flow = Flow::new(Kind::Response, rewrite);
    let (got, learned) = drive_forward(&from, &to, &mut flow, &peer_out);
    assert!(
        contains(&got, b"Location: http://192.168.1.1:1901/dd.xml\r\n"),
        "Location rewritten to the desc listener: {:?}",
        String::from_utf8_lossy(&got)
    );
    assert_eq!(learned, None, "a Location redirect is not a REST endpoint");
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn forward_reports_source_eof_when_the_peer_closes_its_write() {
    let (peer_in, from) = connected_pair();
    let (to, _peer_out) = connected_pair();
    drop(peer_in); // the source's peer closes → `from` observes EOF
    let mut flow = Flow::new(Kind::Request, RewritePolicy::NONE);
    let mut deadline = Instant::now();
    let mut learned_rest = None;
    let outcome = loop {
        let mut ctx = DirectionContext {
            from: &from,
            from_reg: None,
            to: &to,
            to_reg: None,
            flow: &mut flow,
            learned_rest: &mut learned_rest,
            deadline: &mut deadline,
        };
        match ctx.forward() {
            Forwarded::Open => sleep(Duration::from_millis(1)), // FIN not observed yet
            terminal => break terminal,
        }
    };
    assert!(matches!(outcome, Forwarded::SourceEof));
}

/// A reactor plus a `Connection` whose client/device sockets are watched loopback pairs, with the
/// far ends returned so a test can drive traffic and observe what the proxy forwards: `client_peer`
/// stands in for the DIAL client, `device_peer` for the device.
fn watched_connection() -> (Reactor, Connection, TcpSocket, TcpSocket) {
    let mut reactor = Reactor::new().expect("reactor");
    let key = reactor.register(Box::new(NoopHandler));
    let (client_peer, client) = connected_pair(); // the proxy accepted the client
    let (device, device_peer) = connected_pair(); // the proxy connected to the device
    let client_reg = reactor
        .watch(key, client.as_raw_fd(), 0)
        .expect("watch client");
    let device_reg = reactor
        .watch(key, device.as_raw_fd(), 0)
        .expect("watch device");
    let device_endpoint = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 5), 8008);
    // The c2u framer rewrites the request's Host to the device, as `start_connection` wires it; the
    // state-machine tests don't drive a u2c response through the rewrite, so its policy stays empty.
    let c2u_rewrite = RewritePolicy {
        host: Some(device_endpoint),
        application_url: None,
        location: None,
    };
    let conn = Connection {
        client,
        client_reg: Some(client_reg),
        device,
        device_reg: Some(device_reg),
        device_endpoint,
        learned_rest: None,
        c2u: Flow::new(Kind::Request, c2u_rewrite),
        u2c: Flow::new(Kind::Response, RewritePolicy::NONE),
        deadline: Instant::now(),
    };
    (reactor, conn, client_peer, device_peer)
}

/// Read `sock` until EOF, returning everything received (panics if EOF never arrives on loopback).
fn drain_to_eof(sock: &TcpSocket) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    for _ in 0..2000 {
        match sock.recv_bytes(&mut buf).expect("recv") {
            IoStatus::Ready(0) => return out,
            IoStatus::Ready(n) => out.extend_from_slice(&buf[..n]),
            IoStatus::WouldBlock => sleep(Duration::from_millis(1)),
        }
    }
    panic!("EOF never arrived on loopback");
}

/// Drive `forward` on the client→device edge until the flow reaches `Done` (or the budget runs out).
fn drive_c2u_to_done(conn: &mut Connection, reactor: &mut Reactor) {
    for _ in 0..2000 {
        conn.forward(Direction::ClientToDevice, reactor);
        if conn.c2u.state == FlowState::Done {
            return;
        }
        sleep(Duration::from_millis(1));
    }
    panic!("c2u never reached Done");
}

#[test]
#[cfg_attr(miri, ignore = "needs a real poll backend")]
fn close_if_complete_closes_only_when_both_flows_are_done() {
    let (_reactor, mut conn, _client_peer, _device_peer) = watched_connection();
    // Both Open: keep.
    assert_eq!(conn.close_if_complete(Outcome::Keep), Outcome::Keep);
    // One side done, the other still open: keep (the half-close isn't finished).
    conn.c2u.state = FlowState::Done;
    assert_eq!(conn.close_if_complete(Outcome::Keep), Outcome::Keep);
    // Both done: close.
    conn.u2c.state = FlowState::Done;
    assert_eq!(conn.close_if_complete(Outcome::Keep), Outcome::Close);
    // An explicit Close wins regardless of the flow states.
    conn.c2u.state = FlowState::Open;
    conn.u2c.state = FlowState::Open;
    assert_eq!(conn.close_if_complete(Outcome::Close), Outcome::Close);
}

#[test]
#[cfg_attr(miri, ignore = "needs a real poll backend")]
fn forward_eof_finishes_the_flow_and_fins_the_destination() {
    let (mut reactor, mut conn, client_peer, device_peer) = watched_connection();
    // The client sends a full request, then closes its write half (a FIN after the bytes).
    assert!(matches!(
        client_peer
            .send(b"GET /apps HTTP/1.1\r\nHost: 192.168.1.2:80\r\n\r\n")
            .expect("send request"),
        IoStatus::Ready(_)
    ));
    drop(client_peer);
    // The readable edges forward the request (Open), then observe EOF: Open -> SourceClosed ->
    // (empty backlog) -> Done.
    drive_c2u_to_done(&mut conn, &mut reactor);
    assert_eq!(conn.c2u.state, FlowState::Done);
    // The device received the Host-rewritten request and then our FIN (EOF terminates the drain).
    let got = drain_to_eof(&device_peer);
    assert!(
        contains(&got, b"Host: 10.0.0.5:8008\r\n"),
        "request forwarded before the FIN: {:?}",
        String::from_utf8_lossy(&got)
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real poll backend")]
fn half_close_holds_in_source_closed_until_the_backlog_drains() {
    let (mut reactor, mut conn, _client_peer, device_peer) = watched_connection();
    // A backlog still owed to the device at the moment the client half-closes.
    conn.c2u
        .send
        .append(b"GET / HTTP/1.1\r\n\r\n")
        .expect("buffer a backlog");
    // Half-close with bytes still pending: the flow holds at SourceClosed, not Done.
    assert_eq!(
        conn.context(Direction::ClientToDevice)
            .half_close(&mut reactor),
        Outcome::Keep
    );
    assert_eq!(conn.c2u.state, FlowState::SourceClosed);
    // Draining the backlog (a writable edge) then finishes the flow.
    for _ in 0..2000 {
        conn.on_writable(Direction::ClientToDevice, &mut reactor);
        if conn.c2u.state == FlowState::Done {
            break;
        }
        sleep(Duration::from_millis(1));
    }
    assert_eq!(conn.c2u.state, FlowState::Done);
    let got = drain_to_eof(&device_peer);
    assert!(
        got.starts_with(b"GET / HTTP/1.1\r\n"),
        "the backlog reached the device before the FIN: {:?}",
        String::from_utf8_lossy(&got)
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real poll backend")]
fn source_hangup_with_no_backlog_tears_down() {
    let (mut reactor, mut conn, _client_peer, _device_peer) = watched_connection();
    // A readable edge once the flow is past Open is a hangup on the disarmed source. With nothing
    // owed to the live peer, winding down finishes both directions at once -> close.
    conn.c2u.state = FlowState::SourceClosed;
    assert_eq!(
        conn.forward(Direction::ClientToDevice, &mut reactor),
        Outcome::Close
    );
    // Same once the flow is already Done.
    let (mut reactor, mut conn, _client_peer, _device_peer) = watched_connection();
    conn.c2u.state = FlowState::Done;
    assert_eq!(
        conn.forward(Direction::ClientToDevice, &mut reactor),
        Outcome::Close
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real poll backend")]
fn source_hangup_still_drains_the_forward_backlog() {
    let (mut reactor, mut conn, _client_peer, device_peer) = watched_connection();
    // The client half-closed with a request still buffered toward the (live) device...
    conn.c2u
        .send
        .append(b"GET /apps HTTP/1.1\r\n\r\n")
        .expect("buffer a backlog");
    conn.c2u.state = FlowState::SourceClosed;
    // ...then the client fully hangs up: a readable edge on the disarmed source.
    assert_eq!(
        conn.forward(Direction::ClientToDevice, &mut reactor),
        Outcome::Keep,
        "keep the connection to drain the request, don't drop it"
    );
    assert_eq!(
        conn.u2c.state,
        FlowState::Done,
        "the reverse direction is abandoned; the client is gone"
    );
    assert!(
        conn.client_reg.is_none(),
        "the hung-up client fd is unwatched so its HUP stops re-firing"
    );
    // Draining finishes the forward flow; the device receives the whole request, then our FIN.
    for _ in 0..2000 {
        conn.on_writable(Direction::ClientToDevice, &mut reactor);
        if conn.c2u.state == FlowState::Done {
            break;
        }
        sleep(Duration::from_millis(1));
    }
    assert_eq!(conn.c2u.state, FlowState::Done);
    let got = drain_to_eof(&device_peer);
    assert!(
        got.starts_with(b"GET /apps HTTP/1.1\r\n"),
        "the full request reached the device before the FIN: {:?}",
        String::from_utf8_lossy(&got)
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real poll backend")]
fn both_peers_hangup_closes_without_panic() {
    let (mut reactor, mut conn, _client_peer, _device_peer) = watched_connection();
    // Both directions still owe a backlog to their (about-to-vanish) peers.
    conn.c2u.send.append(b"req").expect("buffer c2u");
    conn.u2c.send.append(b"resp").expect("buffer u2c");
    conn.c2u.state = FlowState::SourceClosed;
    conn.u2c.state = FlowState::SourceClosed;
    // The client hangs up: peer_gone keeps the connection to drain the request to the live device.
    assert_eq!(
        conn.forward(Direction::ClientToDevice, &mut reactor),
        Outcome::Keep
    );
    // Then the device hangs up too. Its registration is already gone, so nothing is left to
    // deliver: close, and (the regression) without panicking in settle/sync_write_interest.
    assert_eq!(
        conn.forward(Direction::DeviceToClient, &mut reactor),
        Outcome::Close
    );
}
