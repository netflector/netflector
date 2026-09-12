use std::net::Ipv4Addr;

use super::*;
#[cfg(target_os = "linux")]
use crate::capture::Capture;
#[cfg(target_os = "linux")]
use crate::net::LinkType;
use crate::reflector::NoRewrite;
use crate::test_support::{loopback_lock, open_loopback_or_skip};

const TEST_TTL: u8 = 2;

/// A trivial ingress gate: every payload is a search. The session bookkeeping under test is
/// independent of how a protocol classifies.
fn always_reflect(_: &[u8]) -> Verdict {
    Verdict::Reflect(MessageType::SsdpSearch)
}

/// A fixed session window, standing in for a protocol's window policy.
fn fixed_window(_: &[u8]) -> Duration {
    Duration::from_secs(2)
}

fn never(_: &[u8]) -> bool {
    false
}

const TEST_PROTOCOL: SearchProtocol = SearchProtocol {
    name: "TEST",
    announcement_kind: "announcement",
    port: 1900,
    ttl: TEST_TTL,
    group_v4: Ipv4Addr::new(239, 255, 255, 250),
    groups_v6: &[],
    response_type: MessageType::SsdpResponse,
    announcement_verdict: always_reflect,
    search_verdict: always_reflect,
    window: fixed_window,
    suppress: never,
};

fn no_rewrite() -> Box<dyn Fn() -> Box<dyn ReplyRewrite>> {
    Box::new(|| Box::new(NoRewrite) as Box<dyn ReplyRewrite>)
}

fn test_reflector() -> SearchReflector {
    SearchReflector::new(
        CaptureKey::from_u64(1),
        CaptureKey::from_u64(0),
        Delivery::Link,
        None,
        TEST_PROTOCOL,
        no_rewrite(),
    )
}

/// Push a session for `searcher` onto `reflector`: a real loopback port reservation plus a
/// registered response registration, so eviction has something to tear down. (`PortReservation`
/// binds a socket directly, so no capture / `CAP_NET_RAW` is needed.)
fn push_session(
    reflector: &mut SearchReflector,
    dispatcher: &mut PacketDispatcher,
    searcher: &str,
    dest: &str,
    expiry: Instant,
) {
    let searcher: SocketAddr = searcher.parse().unwrap();
    let dest: SocketAddr = dest.parse().unwrap();
    let (target, source) = (reflector.target, reflector.source);
    let reservation = PortReservation::create(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        .expect("reserve a loopback port");
    let response_key = dispatcher.register(
        target,
        Filter::default(),
        Box::new(SimpleReflector::new(
            source,
            Delivery::Unicast {
                to: searcher,
                mac: MacAddr::from([0; 6]),
            },
            "TEST",
            "response",
            always_reflect,
            Emit::reply(TEST_TTL),
        )),
    );
    reflector.sessions.insert(
        SessionKey { searcher, dest },
        Session {
            expiry,
            reservation,
            response_key,
        },
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn next_deadline_is_the_soonest_session_expiry() {
    let mut dispatcher = PacketDispatcher::new();
    let mut reflector = test_reflector();
    assert_eq!(
        reflector.next_deadline(),
        None,
        "no sessions means no timer"
    );
    let base = Instant::now();
    push_session(
        &mut reflector,
        &mut dispatcher,
        "10.0.0.1:5",
        "239.255.255.250:1900",
        base + Duration::from_secs(5),
    );
    push_session(
        &mut reflector,
        &mut dispatcher,
        "10.0.0.2:5",
        "239.255.255.250:1900",
        base + Duration::from_secs(2),
    );
    assert_eq!(
        reflector.next_deadline(),
        Some(base + Duration::from_secs(2))
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn on_deadline_evicts_expired_sessions_and_unregisters_their_registrations() {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new().unwrap();
    let mut reflector = test_reflector();
    let base = Instant::now();
    push_session(
        &mut reflector,
        &mut dispatcher,
        "10.0.0.1:5",
        "239.255.255.250:1900",
        base,
    ); // already due
    push_session(
        &mut reflector,
        &mut dispatcher,
        "10.0.0.2:5",
        "239.255.255.250:1900",
        base + Duration::from_secs(10),
    ); // live
    assert_eq!(dispatcher.registration_count(), 2);

    reflector.on_deadline(base + Duration::from_secs(1), &mut dispatcher, &mut reactor);

    assert_eq!(
        reflector.sessions.len(),
        1,
        "the expired session is dropped"
    );
    assert_eq!(
        reflector.sessions.iter().next().unwrap().0.searcher,
        "10.0.0.2:5".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        dispatcher.registration_count(),
        1,
        "its response registration is removed with it"
    );
    assert_eq!(
        reflector.next_deadline(),
        Some(base + Duration::from_secs(10))
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn a_retransmit_reuses_its_session_and_refreshes_the_window() {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new().unwrap();
    // A synthetic target: send_udp_group on an unknown egress drops the datagram and returns Ok,
    // so the re-reflect "succeeds" with no real capture; this exercises only the bookkeeping.
    let mut reflector = test_reflector();
    let base = Instant::now();
    push_session(
        &mut reflector,
        &mut dispatcher,
        "10.0.0.7:50000",
        "239.255.255.250:1900",
        base,
    );
    assert_eq!(dispatcher.registration_count(), 1);

    let packet = Packet {
        source: "10.0.0.7:50000".parse().unwrap(),
        dest: "239.255.255.250:1900".parse().unwrap(),
        ttl: TEST_TTL,
        dst_mac: None,
        src_mac: Some(MacAddr::from([0x02, 0, 0, 0, 0, 1])),
        payload: b"a search",
    };
    reflector.on_packet(&packet, &mut dispatcher, &mut reactor);

    assert_eq!(
        reflector.sessions.len(),
        1,
        "a retransmit reuses its session, not a new one"
    );
    assert_eq!(
        dispatcher.registration_count(),
        1,
        "no second response registration is made"
    );
    assert!(
        reflector.sessions.iter().next().unwrap().1.expiry > base,
        "the session's window is refreshed"
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn a_retransmit_with_a_smaller_window_does_not_shorten_the_session() {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new().unwrap();
    let mut reflector = test_reflector();
    // Well past anything the retransmit's own window can reach.
    let far = Instant::now() + Duration::from_hours(1);
    push_session(
        &mut reflector,
        &mut dispatcher,
        "10.0.0.7:50000",
        "239.255.255.250:1900",
        far,
    );

    let packet = Packet {
        source: "10.0.0.7:50000".parse().unwrap(),
        dest: "239.255.255.250:1900".parse().unwrap(),
        ttl: TEST_TTL,
        dst_mac: None,
        src_mac: Some(MacAddr::from([0x02, 0, 0, 0, 0, 1])),
        payload: b"a search",
    };
    reflector.on_packet(&packet, &mut dispatcher, &mut reactor);

    assert_eq!(
        reflector.sessions.iter().next().unwrap().1.expiry,
        far,
        "replies promised by the earlier window are still collected"
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn a_session_is_keyed_by_searcher_and_group() {
    // The dedup key is (searcher, group). One live session for a searcher's link-local search: a
    // retransmit (same searcher, same group) finds it, but the same searcher's site-local search does
    // not — its replies come to a different scope-matched address, so it needs its own session. The
    // bug keyed on the searcher alone, so the site-local search wrongly reused the link-local session.
    let mut dispatcher = PacketDispatcher::new();
    let mut reflector = test_reflector();
    push_session(
        &mut reflector,
        &mut dispatcher,
        "[fe80::1]:50000",
        "[ff02::c]:1900",
        Instant::now(),
    );
    let searcher: SocketAddr = "[fe80::1]:50000".parse().unwrap();
    let link_local: SocketAddr = "[ff02::c]:1900".parse().unwrap();
    let site_local: SocketAddr = "[ff05::c]:1900".parse().unwrap();
    let key = |dest| SessionKey { searcher, dest };
    assert!(reflector.sessions.get(&key(link_local)).is_some());
    assert!(reflector.sessions.get(&key(site_local)).is_none());
}

// on_iface_change drops every session on a capture the reflector uses: a recreation or address
// change orphaned each session's reservation and response registration, so they must go (their
// ports free with the reservations) and the next search re-opens fresh. A change on a capture the
// reflector does not use leaves them.
#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn on_iface_change_clears_sessions_on_a_used_capture() {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new().unwrap();
    let mut reflector = test_reflector();
    let expiry = Instant::now() + Duration::from_secs(5);
    push_session(
        &mut reflector,
        &mut dispatcher,
        "10.0.0.1:5",
        "239.255.255.250:1900",
        expiry,
    );
    push_session(
        &mut reflector,
        &mut dispatcher,
        "10.0.0.2:5",
        "239.255.255.250:1900",
        expiry,
    );
    assert_eq!(dispatcher.registration_count(), 2);

    // A capture the reflector does not use: the sessions stand.
    reflector.on_iface_change(&[CaptureKey::from_u64(42)], &mut dispatcher, &mut reactor);
    assert_eq!(
        reflector.sessions.len(),
        2,
        "a change on an unused capture leaves the sessions"
    );
    assert_eq!(dispatcher.registration_count(), 2);

    // The target capture, shared by every session: all cleared, their response registrations gone.
    let target = reflector.target;
    reflector.on_iface_change(&[target], &mut dispatcher, &mut reactor);
    assert!(
        reflector.sessions.is_empty(),
        "a change on the target capture clears every session"
    );
    assert_eq!(
        dispatcher.registration_count(),
        0,
        "each cleared session's response registration is removed"
    );
}

// A SOURCE capture change leaves sessions intact: the reservation and response registration live
// on the target, and the reply leg only holds the source's (stable) CaptureKey and re-resolves the
// source address at send time, so a source recreation does not orphan anything.
#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn on_iface_change_leaves_sessions_on_a_source_capture_change() {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new().unwrap();
    let mut reflector = test_reflector();
    push_session(
        &mut reflector,
        &mut dispatcher,
        "10.0.0.1:5",
        "239.255.255.250:1900",
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(dispatcher.registration_count(), 1);
    let source = reflector.source;
    reflector.on_iface_change(&[source], &mut dispatcher, &mut reactor);
    assert_eq!(
        reflector.sessions.len(),
        1,
        "a source capture change leaves the session (its reply leg re-resolves)"
    );
    assert_eq!(dispatcher.registration_count(), 1);
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn make_session_drops_at_the_session_cap() {
    // At MAX_SESSIONS in flight a new searcher is dropped; no live session is evicted early.
    let mut dispatcher = PacketDispatcher::new();
    let mut reflector = test_reflector();
    for i in 0..MAX_SESSIONS {
        push_session(
            &mut reflector,
            &mut dispatcher,
            &format!("10.0.0.1:{}", 5000 + i),
            "239.255.255.250:1900",
            Instant::now(),
        );
    }
    assert_eq!(reflector.sessions.len(), MAX_SESSIONS);
    let packet = Packet {
        source: "10.0.0.9:5".parse().unwrap(),
        dest: "239.255.255.250:1900".parse().unwrap(),
        ttl: TEST_TTL,
        dst_mac: None,
        src_mac: Some(MacAddr::from([0x02, 0, 0, 0, 0, 1])),
        payload: b"search",
    };
    let outcome = reflector.make_session(
        &packet,
        &mut dispatcher,
        Instant::now(),
        MessageType::SsdpSearch,
    );
    assert!(matches!(
        outcome,
        Err(Outcome::Dropped(MessageType::SsdpSearch))
    ));
}

// A search off a link without MACs (a tunnel) carries no source MAC; the reply needs none
// there, so the session opens all the same.
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn a_search_without_a_source_mac_opens_a_session() {
    let _serial = loopback_lock();
    let Some(target_cap) = open_loopback_or_skip() else {
        return;
    };
    let mut dispatcher = PacketDispatcher::new();
    let target = dispatcher
        .add_capture(target_cap)
        .expect("add the loopback capture");
    let mut reactor = Reactor::new().expect("reactor");
    let mut reflector = SearchReflector::new(
        CaptureKey::from_u64(999),
        target,
        Delivery::Link,
        None,
        TEST_PROTOCOL,
        no_rewrite(),
    );
    let packet = Packet {
        source: "10.0.0.1:5".parse().unwrap(),
        dest: "239.255.255.250:1900".parse().unwrap(),
        ttl: TEST_TTL,
        dst_mac: None,
        src_mac: None,
        payload: b"M-SEARCH",
    };
    let outcome = reflector.on_packet(&packet, &mut dispatcher, &mut reactor);
    assert_eq!(outcome, Outcome::Reflected(MessageType::SsdpSearch));
    assert_eq!(reflector.sessions.len(), 1);
}

// Peers behind a tunnel are reached by routable addresses, so a session for a link-local
// group must listen on the address its search copies are sent from, or the replies land
// where nothing waits for them.
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn a_session_listens_where_its_search_copies_come_from() -> std::io::Result<()> {
    let Some(tun) = crate::test_support::Tun::create() else {
        return Ok(());
    };
    assert!(tun.add_address("fe80::1/64") && tun.add_address("fd00:99::1/64"));
    let mut dispatcher = PacketDispatcher::new();
    let target = dispatcher.add_capture(Capture::open(&tun.name)?)?;
    let mut reactor = Reactor::new()?;
    let peer: IpAddr = "fd00:99::2".parse().unwrap();
    let mut reflector = SearchReflector::new(
        CaptureKey::from_u64(999),
        target,
        Delivery::Peers(Box::new([peer])),
        None,
        TEST_PROTOCOL,
        no_rewrite(),
    );
    let packet = Packet {
        source: "[fe80::a]:1900".parse().unwrap(),
        dest: "[ff02::c]:1900".parse().unwrap(),
        ttl: TEST_TTL,
        dst_mac: None,
        src_mac: Some(MacAddr::from([0x02, 0, 0, 0, 0, 1])),
        payload: b"M-SEARCH",
    };
    let outcome = reflector.on_packet(&packet, &mut dispatcher, &mut reactor);
    assert_eq!(outcome, Outcome::Reflected(MessageType::SsdpSearch));
    let listening = reflector
        .sessions
        .iter()
        .map(|(_, session)| session.reservation.source())
        .next()
        .expect("a session");

    let deadline = Instant::now() + Duration::from_secs(1);
    let copy = loop {
        let Some(bytes) = tun.next_packet(deadline)? else {
            panic!("the search copy never reached the far end");
        };
        if let Ok(parsed) = Packet::parse(LinkType::RawIp, &bytes)
            && parsed.payload == b"M-SEARCH"
        {
            break (parsed.source, parsed.dest);
        }
    };
    assert_eq!(copy.1, SocketAddr::new(peer, 1900));
    assert_eq!(copy.0, listening);
    Ok(())
}

#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn a_failed_reflect_rolls_back_the_session_registration() {
    let _serial = loopback_lock();
    // make_session makes the response registration before reflecting; if the reflect then fails, that
    // registration must be rolled back, not leaked. A real loopback target lets make_session succeed;
    // an oversized payload then makes build_udp reject the reflect deterministically.
    let Some(target_cap) = open_loopback_or_skip() else {
        return;
    };
    let mut dispatcher = PacketDispatcher::new();
    let target = dispatcher
        .add_capture(target_cap)
        .expect("add the loopback capture");
    let mut reactor = Reactor::new().expect("reactor");
    let mut reflector = SearchReflector::new(
        CaptureKey::from_u64(999), // synthetic source: no reply comes back in this test
        target,
        Delivery::Link,
        None,
        TEST_PROTOCOL,
        no_rewrite(),
    );
    let before = dispatcher.registration_count();
    let packet = Packet {
        source: "10.0.0.1:5".parse().unwrap(),
        dest: "239.255.255.250:1900".parse().unwrap(),
        ttl: TEST_TTL,
        dst_mac: None,
        src_mac: Some(MacAddr::from([0x02, 0, 0, 0, 0, 1])),
        payload: &[0u8; 4096], // too large to build, so the reflect fails and rolls back
    };
    let outcome = reflector.on_packet(&packet, &mut dispatcher, &mut reactor);
    assert!(matches!(outcome, Outcome::Dropped(_)));
    assert_eq!(
        reflector.sessions.len(),
        0,
        "no session survives a failed reflect"
    );
    assert_eq!(
        dispatcher.registration_count(),
        before,
        "make_session's response registration was rolled back"
    );
}
