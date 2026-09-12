use super::lifecycle::RECONCILE_RETRY;
use super::*;
use crate::interface::LOOPBACK_IFACE;
use crate::test_support::{loopback_lock, open_or_skip};
use std::cell::{Cell, RefCell};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::rc::Rc;
use std::time::{Duration, Instant};

impl PacketDispatcher {
    /// The number of live routing registrations, a seam for the SSDP session lifecycle tests.
    pub(crate) fn registration_count(&self) -> usize {
        self.registrations.iter().count()
    }

    /// Inject a raw frame on `egress`, skipping the frame build.
    fn send(&self, egress: CaptureKey, frame: &[u8]) -> io::Result<()> {
        super::egress::send(&self.table, egress, frame)
    }
}

// The reconcile detects a cached identity that moved (corrupted here through the test
// seam, as a recreation would move it) and repairs it in place, then re-arms the slow
// tick. Unprivileged: resolution only, no captures.
#[test]
#[cfg_attr(miri, ignore = "resolves a real interface")]
fn reconcile_repairs_a_moved_identity_and_arms_the_slow_tick() -> io::Result<()> {
    let mut reactor = Reactor::new()?;
    let mut dispatcher = PacketDispatcher::new();
    let key = dispatcher.table.find_or_add_interface(LOOPBACK_IFACE)?;
    let real = crate::interface::if_index(LOOPBACK_IFACE).expect("loopback has an ifindex");
    dispatcher.table.set_test_ifindex(key, real + 1000);
    assert!(!dispatcher.table.stale_interfaces().is_empty());

    dispatcher.reconcile_interfaces(&mut reactor);

    assert!(
        dispatcher.table.stale_interfaces().is_empty(),
        "the moved identity is repaired"
    );
    assert!(
        dispatcher.lifecycle.next_reconcile() > Instant::now() + RECONCILE_RETRY,
        "a healthy table re-arms the slow tick, not the retry"
    );
    Ok(())
}

// A vanished interface parks (identity 0, quiescent thereafter) and keeps the fast retry
// cadence armed, so its return is picked up promptly even with every event lost.
#[test]
#[cfg_attr(miri, ignore = "resolves a real interface")]
fn reconcile_parks_a_vanished_interface_and_keeps_the_fast_retry() -> io::Result<()> {
    let mut reactor = Reactor::new()?;
    let mut dispatcher = PacketDispatcher::new();
    let key = dispatcher.table.find_or_add_interface(LOOPBACK_IFACE)?;
    dispatcher.table.set_test_name(key, "netflector-gone0");

    dispatcher.reconcile_interfaces(&mut reactor);

    assert!(
        dispatcher.table.stale_interfaces().is_empty(),
        "a parked entry is quiescent, not perpetually stale"
    );
    assert!(dispatcher.table.any_absent());
    assert!(
        dispatcher.lifecycle.next_reconcile() <= Instant::now() + RECONCILE_RETRY,
        "an absent interface keeps the fast retry cadence"
    );
    // The interface "returns" (the name resolves again): the next pass rebuilds it.
    dispatcher.table.set_test_name(key, LOOPBACK_IFACE);
    dispatcher.reconcile_interfaces(&mut reactor);
    assert!(
        !dispatcher.table.any_absent(),
        "the returned interface is re-pointed"
    );
    assert!(
        dispatcher.lifecycle.next_reconcile() > Instant::now() + RECONCILE_RETRY,
        "recovery re-arms the slow tick"
    );
    Ok(())
}

// A completed recovery bumps the recoveries count on each of the interface's capture rows.
// Unprivileged: the moved identity is faked through the test seam and the capture row is a
// capture-less test entry (rebind_capture reports it missing, which does not fail the recovery).
#[test]
#[cfg_attr(miri, ignore = "resolves a real interface")]
fn reconcile_counts_a_recovery_on_the_interface_captures() -> io::Result<()> {
    let mut reactor = Reactor::new()?;
    let mut dispatcher = PacketDispatcher::new();
    let key = dispatcher.table.find_or_add_interface(LOOPBACK_IFACE)?;
    let capture = dispatcher.table.add_test_capture(); // links the first interface
    assert_eq!(dispatcher.table.recoveries_of(capture), 0);
    let real = crate::interface::if_index(LOOPBACK_IFACE).expect("loopback has an ifindex");
    dispatcher.table.set_test_ifindex(key, real + 1000); // as a recreation would move it

    dispatcher.reconcile_interfaces(&mut reactor);

    assert_eq!(
        dispatcher.table.recoveries_of(capture),
        1,
        "the completed recovery is counted on the interface's capture row"
    );
    Ok(())
}

fn packet(
    source: &str,
    dest: &str,
    dst_mac: Option<MacAddr>,
    src_mac: Option<MacAddr>,
) -> Packet<'static> {
    Packet {
        source: source.parse().unwrap(),
        dest: dest.parse().unwrap(),
        ttl: 64,
        dst_mac,
        src_mac,
        payload: b"",
    }
}

/// A loopback probe rig: a bound `receiver` (its port reserved so the probe has a real
/// destination; the probe is captured off `lo`, never recv'd), the `target` to send to,
/// and a `sender`. The caller holds the receiver alive for the test's duration.
fn probe_rig() -> io::Result<(UdpSocket, SocketAddr, UdpSocket)> {
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    let target = receiver.local_addr()?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    Ok((receiver, target, sender))
}

/// Call `step`, then sleep 20 ms, until `done` is true or `secs` elapse: the drive loop
/// for a non-blocking driver like `drain_and_route`. (The reactor test's `poll_once` loop
/// blocks on its own timeout instead, so it isn't routed through here.)
fn pump_until(secs: u64, mut done: impl FnMut() -> bool, mut step: impl FnMut()) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() && Instant::now() < deadline {
        step();
        if !done() {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn wildcard_filter_matches_anything() {
    assert!(Filter::default().matches(&packet("10.0.0.1:1", "10.0.0.2:2", None, None), None));
}

#[test]
fn filter_matches_destination_group_and_port() {
    let f = Filter {
        dst_ip: Some("224.0.0.251".parse::<IpAddr>().unwrap().into()),
        dst_port: Some(5353.into()),
        ..Filter::default()
    };
    assert!(f.matches(
        &packet("10.0.0.1:5353", "224.0.0.251:5353", None, None),
        None
    ));
    // Wrong group, and wrong port, each miss.
    assert!(!f.matches(
        &packet("10.0.0.1:5353", "224.0.0.252:5353", None, None),
        None
    ));
    assert!(!f.matches(
        &packet("10.0.0.1:5353", "224.0.0.251:1900", None, None),
        None
    ));
}

#[test]
fn filter_dst_own_widens_dst_ip_to_the_ingress_addresses() {
    let group: IpAddr = "224.0.0.251".parse().unwrap();
    let ingress = InterfaceAddresses::new(
        None,
        Some(Ipv4Addr::new(10, 0, 0, 1)),
        Some("fe80::1".parse().unwrap()),
        Some("fd00::1".parse().unwrap()),
    );
    let widened = Filter {
        dst_ip: Some(group.into()),
        dst_own: Some(AddressFamily::Dual),
        ..Filter::default()
    };
    assert!(widened.matches(
        &packet("10.0.0.2:1", "224.0.0.251:9", None, None),
        Some(&ingress)
    ));
    // Every address the ingress owns, in either family.
    for own in ["10.0.0.1:9", "[fe80::1]:9", "[fd00::1]:9"] {
        assert!(widened.matches(&packet("10.0.0.2:1", own, None, None), Some(&ingress)));
    }
    // Only the families the widening names: an answer of the other family is not taken.
    let v4_only = Filter {
        dst_own: Some(AddressFamily::Ipv4),
        ..widened.clone()
    };
    assert!(v4_only.matches(
        &packet("10.0.0.2:1", "10.0.0.1:9", None, None),
        Some(&ingress)
    ));
    assert!(!v4_only.matches(
        &packet("[fe80::2]:1", "[fe80::1]:9", None, None),
        Some(&ingress)
    ));
    let v6_only = Filter {
        dst_own: Some(AddressFamily::Ipv6),
        ..widened.clone()
    };
    assert!(v6_only.matches(
        &packet("[fe80::2]:1", "[fd00::1]:9", None, None),
        Some(&ingress)
    ));
    assert!(!v6_only.matches(
        &packet("10.0.0.2:1", "10.0.0.1:9", None, None),
        Some(&ingress)
    ));
    // Another host's address, and an ingress with no known addresses, both miss.
    assert!(!widened.matches(
        &packet("10.0.0.2:1", "10.0.0.3:9", None, None),
        Some(&ingress)
    ));
    assert!(!widened.matches(&packet("10.0.0.2:1", "10.0.0.1:9", None, None), None));
    // Without the widening the group alone matches.
    let group_only = Filter {
        dst_ip: Some(group.into()),
        ..Filter::default()
    };
    assert!(!group_only.matches(
        &packet("10.0.0.2:1", "10.0.0.1:9", None, None),
        Some(&ingress)
    ));
}

#[test]
fn filter_broadcast_takes_the_all_ones_mac_or_the_limited_broadcast() {
    let f = Filter {
        broadcast: true,
        ..Filter::default()
    };
    let all_ones = Some(MacAddr::broadcast());
    let unicast = Some(MacAddr::from([0x02, 0, 0, 0, 0, 1]));
    // The ingress owns 10.0.0.1/24, so its directed broadcast is 10.0.0.255.
    let ingress = InterfaceAddresses::new(None, Some(Ipv4Addr::new(10, 0, 0, 1)), None, None)
        .with_v4_prefix(24);
    let own = Some(&ingress);
    // On the all-ones MAC every subnet's directed broadcast qualifies, the limited one too.
    assert!(f.matches(&packet("10.0.0.1:1", "10.0.0.255:9", all_ones, None), own));
    assert!(f.matches(&packet("10.0.1.1:1", "10.0.1.255:9", all_ones, None), own));
    assert!(f.matches(
        &packet("10.0.0.1:1", "255.255.255.255:9", all_ones, None),
        own
    ));
    // Without MACs (DLT_NULL) the address decides: the limited broadcast, or the link's own.
    assert!(f.matches(&packet("10.0.0.1:1", "255.255.255.255:9", None, None), own));
    assert!(f.matches(&packet("10.0.0.1:1", "10.0.0.255:9", None, None), own));
    assert!(!f.matches(&packet("10.0.1.1:1", "10.0.1.255:9", None, None), own));
    assert!(!f.matches(&packet("10.0.0.1:1", "10.0.0.255:9", None, None), None));
    // The frame decides, not the address's shape: a broadcast-looking address on a unicast
    // frame is unicast, a unicast-looking one on the all-ones MAC is a broadcast of a subnet
    // the sender knows.
    assert!(!f.matches(&packet("10.0.0.1:1", "10.0.0.255:9", unicast, None), own));
    assert!(f.matches(&packet("10.0.0.1:1", "10.0.0.2:9", all_ones, None), own));
    assert!(!f.matches(&packet("10.0.0.1:1", "224.0.0.251:9", None, None), own));
    // A group on the all-ones MAC is still a group: the group handler's, not this one's.
    assert!(!f.matches(&packet("10.0.0.1:1", "224.0.0.251:9", all_ones, None), own));
    assert!(!f.matches(&packet("[fe80::1]:1", "[ff02::1]:9", all_ones, None), own));
}

#[test]
fn filter_dst_ip_set_matches_any_group() {
    // One handler spanning the v4 and v6 mDNS groups: either destination matches.
    let f = Filter {
        dst_ip: Some(
            [
                "224.0.0.251".parse::<IpAddr>().unwrap(),
                "ff02::fb".parse().unwrap(),
            ]
            .into(),
        ),
        dst_port: Some(5353.into()),
        ..Filter::default()
    };
    assert!(f.matches(
        &packet("10.0.0.1:5353", "224.0.0.251:5353", None, None),
        None
    ));
    assert!(f.matches(
        &packet("[fe80::1]:5353", "[ff02::fb]:5353", None, None),
        None
    ));
    // A group outside the set, and a member on the wrong port, each miss.
    assert!(!f.matches(
        &packet("10.0.0.1:5353", "239.255.255.250:5353", None, None),
        None
    ));
    assert!(!f.matches(
        &packet("10.0.0.1:5353", "224.0.0.251:1900", None, None),
        None
    ));
}

#[test]
fn filter_dst_port_set_matches_any_port() {
    // One handler spanning WoL ports 7 and 9: either destination port matches.
    let f = Filter {
        dst_port: Some([7u16, 9].into()),
        ..Filter::default()
    };
    assert!(f.matches(&packet("10.0.0.1:1", "255.255.255.255:7", None, None), None));
    assert!(f.matches(&packet("10.0.0.1:1", "255.255.255.255:9", None, None), None));
    // A port outside the set misses.
    assert!(!f.matches(&packet("10.0.0.1:1", "255.255.255.255:8", None, None), None));
}

#[test]
fn filter_matches_source_mac_and_excludes_others() {
    let device = MacAddr::from([0x02, 0, 0, 0, 0, 0x01]);
    let f = Filter {
        src_mac: Some(MacSet::from(device)),
        ..Filter::default()
    };
    assert!(f.matches(
        &packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(device)),
        None
    ));
    // A different device, and a MAC-less (DLT_NULL) packet, both miss.
    let other = MacAddr::from([0x02, 0, 0, 0, 0, 0x02]);
    assert!(!f.matches(
        &packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(other)),
        None
    ));
    assert!(!f.matches(&packet("10.0.0.1:5353", "10.0.0.2:5353", None, None), None));
}

#[test]
fn filter_source_mac_set_matches_any_member() {
    let a = MacAddr::from([0x02, 0, 0, 0, 0, 0x01]);
    let b = MacAddr::from([0x02, 0, 0, 0, 0, 0x02]);
    let f = Filter {
        src_mac: Some(MacSet::try_from(vec![a, b]).unwrap()),
        ..Filter::default()
    };
    assert!(f.matches(
        &packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(a)),
        None
    ));
    assert!(f.matches(
        &packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(b)),
        None
    ));
    // A device outside the set misses.
    let other = MacAddr::from([0x02, 0, 0, 0, 0, 0x03]);
    assert!(!f.matches(
        &packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(other)),
        None
    ));
}

#[test]
fn filter_matches_destination_mac_and_excludes_others() {
    let device = MacAddr::from([0x02, 0, 0, 0, 0, 0x0a]);
    let f = Filter {
        dst_mac: Some(device),
        ..Filter::default()
    };
    assert!(f.matches(
        &packet("10.0.0.1:5353", "10.0.0.2:5353", Some(device), None),
        None
    ));
    let other = MacAddr::from([0x02, 0, 0, 0, 0, 0x0b]);
    assert!(!f.matches(
        &packet("10.0.0.1:5353", "10.0.0.2:5353", Some(other), None),
        None
    ));
    assert!(!f.matches(&packet("10.0.0.1:5353", "10.0.0.2:5353", None, None), None));
}

// An IP filter is family-specific: a v4 criterion can't match a v6 packet, or vice
// versa (`IpAddr`'s `PartialEq` is cross-family-aware).
#[test]
fn filter_ip_does_not_match_across_families() {
    let v4 = Filter {
        dst_ip: Some("224.0.0.251".parse::<IpAddr>().unwrap().into()),
        ..Filter::default()
    };
    assert!(!v4.matches(
        &packet("[fe80::1]:5353", "[ff02::fb]:5353", None, None),
        None
    ));
    let v6 = Filter {
        dst_ip: Some("ff02::fb".parse::<IpAddr>().unwrap().into()),
        ..Filter::default()
    };
    assert!(!v6.matches(
        &packet("10.0.0.1:5353", "224.0.0.251:5353", None, None),
        None
    ));
}

const PROBE: &[u8] = b"netflector-dispatch-probe";
/// The echo re-emits to this port, distinct from the filter's, so the looped-back
/// echo can't re-match and amplify.
const ECHO_DST_PORT: u16 = 1;

/// Each entry: the payload a reflector saw, and whether its keyed egress succeeded.
type Seen = Rc<RefCell<Vec<(Vec<u8>, bool)>>>;

/// A reflector that re-emits each matched packet on its egress capture (by key,
/// through the dispatcher) and records what it saw. The seam `WoL` et al. will fill.
struct Echo {
    egress: CaptureKey,
    seen: Seen,
}

impl PacketHandler for Echo {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) -> Outcome {
        let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (packet.source, packet.dest) else {
            return Outcome::Filtered;
        };
        let dst = SocketAddr::V4(SocketAddrV4::new(*dst.ip(), ECHO_DST_PORT));
        // Re-emit through the real link-aware send so the framing matches the egress link type
        // (Ethernet vs DLT_NULL) instead of a hardcoded Ethernet frame, which a DLT_NULL loopback
        // (the BSDs) rejects.
        let sent = dispatcher
            .send_udp(
                self.egress,
                dst,
                MacAddr::from([0xff; 6]),
                DatagramSource::Egress { port: src.port() },
                packet.ttl,
                packet.payload,
            )
            .is_ok();
        self.seen.borrow_mut().push((packet.payload.to_vec(), sent));
        Outcome::Reflected(MessageType::MdnsQuery)
    }
}

// End-to-end over loopback: a dispatcher owning two `lo` captures drains a looped
// UDP probe off the ingress key, routes it through the matching Echo reflector,
// which re-emits on the *egress* key. Skips without capture access (no CAP_NET_RAW).
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn routes_a_captured_packet_to_a_matching_reflector() -> io::Result<()> {
    let _serial = loopback_lock();
    let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_ingress")? else {
        return Ok(());
    };
    let Some(egress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_egress")? else {
        return Ok(());
    };

    let (_receiver, target, sender) = probe_rig()?;

    let mut dispatcher = PacketDispatcher::new();
    let ingress = dispatcher.add_capture(ingress_cap)?;
    let egress = dispatcher.add_capture(egress_cap)?;
    // The egress capture resolves to its interface's address, the seam reflectors read.
    assert_eq!(
        dispatcher
            .egress_addrs(egress)
            .and_then(InterfaceAddresses::v4),
        Some(Ipv4Addr::LOCALHOST),
    );
    let seen = Rc::new(RefCell::new(Vec::new()));
    dispatcher.register(
        ingress,
        Filter {
            dst_port: Some(target.port().into()),
            ..Filter::default()
        },
        Box::new(Echo {
            egress,
            seen: seen.clone(),
        }),
    );

    let mut reactor = Reactor::new()?;
    sender.send_to(PROBE, target)?;
    pump_until(
        2,
        || !seen.borrow().is_empty(),
        || dispatcher.drain_and_route(ingress, &mut reactor),
    );

    let records = seen.borrow();
    assert!(!records.is_empty(), "the reflector never fired");
    assert_eq!(records[0].0, PROBE, "reflector saw the wrong payload");
    assert!(records[0].1, "the keyed egress send failed");
    Ok(())
}

/// Every `sood` datagram out of the tun's far end within a second: source, destination, TTL.
#[cfg(target_os = "linux")]
fn sood_deliveries(
    tun: &crate::test_support::Tun,
) -> io::Result<Vec<(SocketAddr, SocketAddr, u8)>> {
    let mut delivered = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(1);
    while let Some(packet) = tun.next_packet(deadline)? {
        if let Ok(parsed) = Packet::parse(LinkType::RawIp, &packet)
            && parsed.payload == b"sood"
        {
            delivered.push((parsed.source, parsed.dest, parsed.ttl));
        }
    }
    Ok(delivered)
}

// Peers behind a raw IP link: a group send fans out to one unicast copy per peer of the
// group's family, at the group's port, and a second relay of the same packet adds nothing.
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn group_sends_fan_out_to_the_peers_of_a_raw_ip_link() -> io::Result<()> {
    let Some(tun) = crate::test_support::Tun::create() else {
        return Ok(());
    };
    let mut dispatcher = PacketDispatcher::new();
    let egress = dispatcher.add_capture(Capture::open(&tun.name)?)?;
    let peers: [IpAddr; 3] = [
        "10.99.200.2".parse().unwrap(),
        "10.99.200.3".parse().unwrap(),
        "fd00:99::2".parse().unwrap(),
    ];

    let group: SocketAddr = "239.255.90.90:9003".parse().unwrap();
    let source: SocketAddr = "192.0.2.7:40001".parse().unwrap();
    // Two handlers relaying one routed packet: the second fan-out duplicates the first.
    dispatcher.egress.begin_packet();
    for _ in 0..2 {
        dispatcher.send_udp_to_peers(
            egress,
            &peers,
            group,
            DatagramSource::Exact(source),
            32,
            b"sood",
        )?;
    }

    let to = |peer: &str| -> SocketAddr { format!("{peer}:9003").parse().unwrap() };
    assert_eq!(
        sood_deliveries(&tun)?,
        [
            (source, to("10.99.200.2"), 32),
            (source, to("10.99.200.3"), 32)
        ]
    );
    Ok(())
}

// Two entries whose peer lists overlap relay one packet: each peer gets it once, whatever
// the lists' order or other members.
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn overlapping_peer_lists_deliver_to_each_peer_once() -> io::Result<()> {
    let Some(tun) = crate::test_support::Tun::create() else {
        return Ok(());
    };
    let mut dispatcher = PacketDispatcher::new();
    let egress = dispatcher.add_capture(Capture::open(&tun.name)?)?;
    let peer = |host: u8| IpAddr::V4(Ipv4Addr::new(10, 99, 200, host));
    let (x, y, z) = (peer(2), peer(3), peer(4));
    let group: SocketAddr = "239.255.90.90:9003".parse().unwrap();
    let source: SocketAddr = "192.0.2.7:40001".parse().unwrap();
    dispatcher.egress.begin_packet();
    for list in [[x, y], [y, z]] {
        dispatcher.send_udp_to_peers(
            egress,
            &list,
            group,
            DatagramSource::Exact(source),
            32,
            b"sood",
        )?;
    }

    let delivered: Vec<IpAddr> = sood_deliveries(&tun)?
        .into_iter()
        .map(|(_, dest, _)| dest.ip())
        .collect();
    assert_eq!(delivered, [x, y, z]);
    Ok(())
}

// 10.0.1.2 and 10.1.1.1 sum to the same checksum words, so their frames differ only in the
// destination; each peer must still get its copy.
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn peers_whose_frames_share_a_checksum_each_get_a_copy() -> io::Result<()> {
    let Some(tun) = crate::test_support::Tun::create() else {
        return Ok(());
    };
    let mut dispatcher = PacketDispatcher::new();
    let egress = dispatcher.add_capture(Capture::open(&tun.name)?)?;
    let peers: [IpAddr; 2] = ["10.0.1.2".parse().unwrap(), "10.1.1.1".parse().unwrap()];
    let group: SocketAddr = "239.255.90.90:9003".parse().unwrap();
    let source: SocketAddr = "192.0.2.7:40001".parse().unwrap();
    dispatcher.egress.begin_packet();
    dispatcher.send_udp_to_peers(
        egress,
        &peers,
        group,
        DatagramSource::Exact(source),
        32,
        b"sood",
    )?;
    let delivered: Vec<IpAddr> = sood_deliveries(&tun)?
        .into_iter()
        .map(|(_, dest, _)| dest.ip())
        .collect();
    assert_eq!(delivered, peers);
    Ok(())
}

// A query relayed to a peer as unicast is answered by unicast to this host; the mDNS response
// leg takes that answer off the tunnel and puts it on the source segment's group.
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn a_unicast_mdns_answer_from_a_peer_goes_to_the_group() -> io::Result<()> {
    use std::io::Write as _;

    use crate::net::frame;
    use crate::net::mdns::{MDNS_GROUP_V4, MDNS_PORT};
    use crate::reflector::{InterfaceMap, mdns};

    let _serial = loopback_lock();
    let Some(mut tun) = crate::test_support::Tun::create() else {
        return Ok(());
    };
    assert!(tun.add_address("10.99.200.1/24"));
    let mut dispatcher = PacketDispatcher::without_group_joins();
    let source = dispatcher.add_capture(Capture::open(LOOPBACK_IFACE)?)?;
    let target = dispatcher.add_capture(Capture::open(&tun.name)?)?;
    let mut interfaces = InterfaceMap::default();
    interfaces.insert(LOOPBACK_IFACE.to_owned(), source);
    interfaces.insert(tun.name.clone(), target);
    let entry = crate::config::Config::from_sources(
        Some(&format!(
            "[reflectors.a]\nsource_if = \"{LOOPBACK_IFACE}\"\ntarget_if = \"{}\"\n\
                 mdns = true\naddress_family = \"ipv4\"\ntarget_peers = [\"10.99.200.2\"]\n",
            tun.name
        )),
        std::iter::empty(),
    )
    .expect("a valid configuration")
    .reflectors
    .remove(0);
    mdns::build(&entry, &interfaces, &mut dispatcher).expect("build the mDNS reflector");
    let mut observer = Capture::open(LOOPBACK_IFACE)?;

    // A DNS header with QR set: a response with no records.
    let answer = [0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut packet = [0u8; 64];
    let n = frame::ipv4_udp(
        SocketAddrV4::new(Ipv4Addr::new(10, 99, 200, 2), MDNS_PORT),
        SocketAddrV4::new(Ipv4Addr::new(10, 99, 200, 1), MDNS_PORT),
        255,
        &answer,
        &mut packet,
    )
    .expect("build the answer");
    tun.far_end.write_all(&packet[..n])?;

    let mut reactor = Reactor::new()?;
    let mut relayed = None;
    pump_until(
        2,
        || {
            while relayed.is_none()
                && let Some(read) = observer.next_frame().unwrap()
            {
                if let Read::Frame(frame) = read
                    && let Ok(parsed) = Packet::parse(LinkType::Ethernet, frame)
                    && parsed.payload == answer
                {
                    relayed = Some((parsed.source, parsed.dest));
                }
            }
            relayed.is_some()
        },
        || dispatcher.drain_and_route(target, &mut reactor),
    );
    assert_eq!(
        relayed,
        Some((
            SocketAddr::from((Ipv4Addr::LOCALHOST, MDNS_PORT)),
            SocketAddr::from((MDNS_GROUP_V4, MDNS_PORT)),
        )),
        "the answer was not relayed to the group on the source side"
    );
    Ok(())
}

/// A `WireGuard` interface with two peers, one with an endpoint and one without. FreeBSD
/// only: `wg` ships in base there, and the interface is created as root.
#[cfg(target_os = "freebsd")]
struct WgPeers {
    name: String,
    reachable: IpAddr,
    unreachable: IpAddr,
}

#[cfg(target_os = "freebsd")]
impl WgPeers {
    /// The endpoint the reachable peer's handshake goes to.
    const ENDPOINT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51820);

    /// `None`, with a note, where the test can't run: not root, or the static build, whose
    /// process spawning crashes (see the pair tests).
    fn create() -> Option<Self> {
        if cfg!(target_feature = "crt-static") {
            eprintln!("skip wg test: process spawning crashes static FreeBSD binaries");
            return None;
        }
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skip wg test: interface creation requires root");
            return None;
        }
        let name = sh_output("ifconfig wg create")?;
        let this = Self {
            name,
            reachable: IpAddr::V4(Ipv4Addr::new(10, 99, 77, 2)),
            unreachable: IpAddr::V4(Ipv4Addr::new(10, 99, 77, 3)),
        };
        let key = std::env::temp_dir().join(format!("netflector-{}.key", this.name));
        let configured = sh(&format!(
            "umask 077 && wg genkey > {key} && wg set {name} private-key {key} listen-port 0 \
                 peer $(wg genkey | wg pubkey) allowed-ips {reachable}/32 endpoint {endpoint} \
                 peer $(wg genkey | wg pubkey) allowed-ips {unreachable}/32 \
                 && ifconfig {name} inet 10.99.77.1/24 up",
            key = key.display(),
            name = this.name,
            reachable = this.reachable,
            unreachable = this.unreachable,
            endpoint = Self::ENDPOINT,
        ));
        std::fs::remove_file(&key).ok();
        assert!(configured, "could not configure {}", this.name);
        Some(this)
    }
}

#[cfg(target_os = "freebsd")]
impl Drop for WgPeers {
    fn drop(&mut self) {
        sh(&format!("ifconfig {} destroy", self.name));
    }
}

/// Run `command` through the shell, succeeding only on exit 0.
#[cfg(target_os = "freebsd")]
fn sh(command: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-ec", command])
        .status()
        .is_ok_and(|status| status.success())
}

/// Run `command` through the shell and return its trimmed stdout, `None` on failure.
#[cfg(target_os = "freebsd")]
fn sh_output(command: &str) -> Option<String> {
    let output = std::process::Command::new("sh")
        .args(["-ec", command])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

// WireGuard refuses a copy for a peer it has no endpoint for, and on FreeBSD the BPF write
// reports that at once. The other peers still get theirs: the send counts as delivered, and
// the reachable peer's handshake shows up at its endpoint. Only when every copy fails does
// the send fail.
#[cfg(target_os = "freebsd")]
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn a_peer_without_an_endpoint_costs_only_its_own_copy() -> io::Result<()> {
    let Some(wg) = WgPeers::create() else {
        return Ok(());
    };
    let endpoint = UdpSocket::bind(WgPeers::ENDPOINT)?;
    endpoint.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut dispatcher = PacketDispatcher::new();
    let egress = dispatcher.add_capture(Capture::open(&wg.name)?)?;
    let group: SocketAddr = "239.255.90.90:9003".parse().unwrap();
    let source = DatagramSource::Egress { port: 40000 };

    let peers = [wg.unreachable, wg.reachable];
    dispatcher.send_udp_to_peers(egress, &peers, group, source, 1, b"sood")?;
    let mut buf = [0u8; 256];
    let (n, from) = endpoint.recv_from(&mut buf)?;
    assert!(n > 0, "the reachable peer's handshake never reached {from}");

    let only_unreachable = [wg.unreachable];
    let failed = dispatcher.send_udp_to_peers(egress, &only_unreachable, group, source, 1, b"sood");
    assert_eq!(
        failed.map_err(|e| e.raw_os_error()),
        Err(Some(libc::EHOSTUNREACH))
    );
    Ok(())
}

/// A reflector that records each matched packet's payload, for routing/registration tests
/// that need no real egress (no capture, no send).
struct Recorder {
    seen: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl PacketHandler for Recorder {
    fn on_packet(&mut self, packet: &Packet, _: &mut PacketDispatcher, _: &mut Reactor) -> Outcome {
        self.seen.borrow_mut().push(packet.payload.to_vec());
        Outcome::Reflected(MessageType::MdnsQuery)
    }
}

/// A synthetic v4 UDP packet for routing tests; the default filter matches it.
fn probe_packet(payload: &[u8]) -> Packet<'_> {
    Packet {
        source: "10.0.0.1:5".parse().unwrap(),
        dest: "10.0.0.2:9".parse().unwrap(),
        ttl: 64,
        dst_mac: None,
        src_mac: None,
        payload,
    }
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn unregister_stops_routing_to_a_handler() -> io::Result<()> {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new()?;
    let ingress = dispatcher.add_test_capture();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let key = dispatcher.register(
        ingress,
        Filter::default(),
        Box::new(Recorder { seen: seen.clone() }),
    );
    dispatcher.route(ingress, &probe_packet(b"a"), &mut reactor);
    assert_eq!(seen.borrow().len(), 1, "the registration should route once");

    dispatcher.unregister(key);
    dispatcher.route(ingress, &probe_packet(b"b"), &mut reactor);
    assert_eq!(
        seen.borrow().len(),
        1,
        "an unregistered handler is no longer routed to"
    );
    dispatcher.unregister(key); // the now-stale key removes nothing
    Ok(())
}

/// A reflector that returns a preset [`Outcome`], driving `route`'s outcome fold and per-capture
/// recording without a real egress.
struct Outcomer(Outcome);

impl PacketHandler for Outcomer {
    fn on_packet(&mut self, _: &Packet, _: &mut PacketDispatcher, _: &mut Reactor) -> Outcome {
        self.0
    }
}

impl PacketDispatcher {
    /// Add a capture-less table entry so a routing test can mint a valid `CaptureKey` and
    /// exercise `route`'s record path without opening a real capture; read the row back with
    /// [`counts`](Self::counts).
    fn add_test_capture(&mut self) -> CaptureKey {
        self.table.add_test_capture()
    }

    /// The `(reflected, skipped, dropped, stalled)` count recorded for `ty` on `key`'s row.
    fn counts(&self, key: CaptureKey, ty: MessageType) -> (u64, u64, u64, u64) {
        self.table.typed_counts(key, ty)
    }
}

// route folds every matched handler's outcome into one and records it once on the ingress row:
// a reflect and its mirror skip (both matching) count a single reflect, and a handler whose filter
// misses doesn't contribute at all.
#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn route_folds_matched_outcomes_and_records_once() -> io::Result<()> {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new()?;
    let ingress = dispatcher.add_test_capture();

    // Mirrored a->b / b->a reflectors both match here: one reflects the query, its mirror skips it.
    dispatcher.register(
        ingress,
        Filter::default(),
        Box::new(Outcomer(Outcome::Reflected(MessageType::MdnsQuery))),
    );
    dispatcher.register(
        ingress,
        Filter::default(),
        Box::new(Outcomer(Outcome::Skipped(MessageType::MdnsQuery))),
    );
    // A third handler whose filter never matches (wrong dst port) must not reach the count.
    dispatcher.register(
        ingress,
        Filter {
            dst_port: Some(4242.into()),
            ..Filter::default()
        },
        Box::new(Outcomer(Outcome::Reflected(MessageType::SsdpSearch))),
    );

    dispatcher.route(ingress, &probe_packet(b"q"), &mut reactor);

    // The reflect wins the fold and is counted once; the skip is shadowed, not a second count.
    assert_eq!(
        dispatcher.counts(ingress, MessageType::MdnsQuery),
        (1, 0, 0, 0)
    );
    // The unmatched handler contributed nothing.
    assert_eq!(
        dispatcher.counts(ingress, MessageType::SsdpSearch),
        (0, 0, 0, 0)
    );
    Ok(())
}

#[test]
fn is_own_echo_matches_the_ingress_mac_except_all_zeros() {
    let own = MacAddr::from([0x02, 0, 0, 0, 0, 1]);
    let other = MacAddr::from([0x02, 0, 0, 0, 0, 2]);
    assert!(is_own_echo(Some(own), Some(own)));
    assert!(!is_own_echo(Some(other), Some(own)));
    // A DLT_NULL frame carries no MAC; an interface without one owns nothing.
    assert!(!is_own_echo(None, Some(own)));
    assert!(!is_own_echo(Some(own), None));
    // Linux loopback: zeros on both sides identify nothing.
    let zero = MacAddr::from([0; 6]);
    assert!(!is_own_echo(Some(zero), Some(zero)));
}

// A frame whose source MAC is the ingress's own is our own re-emit handed back by the link: it
// reaches no handler and counts as echoed, while a peer's frame routes as usual.
#[test]
#[cfg_attr(miri, ignore = "needs a real socket and interface")]
fn route_drops_our_own_echoed_frames_before_any_handler() -> io::Result<()> {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new()?;
    // The capture-less entry links to interface 0: give that interface a known MAC.
    let interface = dispatcher.table.find_or_add_interface(LOOPBACK_IFACE)?;
    let own = MacAddr::from([0x02, 0, 0, 0, 0, 1]);
    dispatcher.table.set_test_addrs(
        interface,
        InterfaceAddresses::new(Some(own), Some(Ipv4Addr::LOCALHOST), None, None),
    );
    let ingress = dispatcher.add_test_capture();
    assert_eq!(dispatcher.table.interface_of(ingress), Some(interface));
    dispatcher.register(
        ingress,
        Filter::default(),
        Box::new(Outcomer(Outcome::Reflected(MessageType::MdnsQuery))),
    );

    let mut echo = probe_packet(b"ours");
    echo.src_mac = Some(own);
    dispatcher.route(ingress, &echo, &mut reactor);
    assert_eq!(dispatcher.table.echoed_of(ingress), 1);
    assert_eq!(
        dispatcher.counts(ingress, MessageType::MdnsQuery),
        (0, 0, 0, 0),
        "the handler never ran"
    );

    let mut peer = probe_packet(b"theirs");
    peer.src_mac = Some(MacAddr::from([0x02, 0, 0, 0, 0, 2]));
    dispatcher.route(ingress, &peer, &mut reactor);
    assert_eq!(
        dispatcher.counts(ingress, MessageType::MdnsQuery),
        (1, 0, 0, 0)
    );
    assert_eq!(dispatcher.table.echoed_of(ingress), 1);
    Ok(())
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn route_folds_fan_out_reflects_and_records_once() -> io::Result<()> {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new()?;
    let ingress = dispatcher.add_test_capture();

    // A source fanned out to two targets (a->b, a->c) puts two reflecting handlers on the shared
    // ingress; both reflect the same query. A legal config, not a duplicate-reflector bug.
    dispatcher.register(
        ingress,
        Filter::default(),
        Box::new(Outcomer(Outcome::Reflected(MessageType::MdnsQuery))),
    );
    dispatcher.register(
        ingress,
        Filter::default(),
        Box::new(Outcomer(Outcome::Reflected(MessageType::MdnsQuery))),
    );

    dispatcher.route(ingress, &probe_packet(b"q"), &mut reactor);

    // One packet, one count per ingress: the two reflects fold to a single reflected count.
    assert_eq!(
        dispatcher.counts(ingress, MessageType::MdnsQuery),
        (1, 0, 0, 0)
    );
    Ok(())
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn counter_report_fires_on_its_interval() -> io::Result<()> {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new()?;
    let now = Instant::now();
    assert_eq!(
        dispatcher.next_deadline(),
        Some(dispatcher.lifecycle.next_reconcile()),
        "until enabled, the only standing deadline is the reconcile tick"
    );

    // Shorter than RECONCILE_TICK, so the report deadline is the min() at each assert.
    let interval = Duration::from_secs(5);
    dispatcher.enable_counter_report(interval, now);
    assert_eq!(dispatcher.next_deadline(), Some(now + interval));

    // Firing the report at its deadline reschedules it exactly one interval out.
    dispatcher.on_deadline(now + interval, &mut reactor);
    assert_eq!(dispatcher.next_deadline(), Some(now + interval + interval));
    Ok(())
}

/// A reflector carrying only a timer: reports `deadline` and counts each `on_deadline` sweep,
/// for the dispatcher's deadline aggregation/dispatch, with no packets involved.
struct Ticker {
    deadline: Option<Instant>,
    fired: Rc<Cell<u32>>,
}

impl PacketHandler for Ticker {
    fn on_packet(&mut self, _: &Packet, _: &mut PacketDispatcher, _: &mut Reactor) -> Outcome {
        Outcome::Filtered
    }
    fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }
    fn on_deadline(&mut self, _now: Instant, _: &mut PacketDispatcher, _: &mut Reactor) {
        self.fired.set(self.fired.get() + 1);
    }
}

#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn reports_the_soonest_deadline_and_sweeps_only_the_due_one() -> io::Result<()> {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new()?;
    let ingress = CaptureKey::from_u64(0);
    let base = Instant::now();
    let due = Rc::new(Cell::new(0u32));
    let future = Rc::new(Cell::new(0u32));
    dispatcher.register(
        ingress,
        Filter::default(),
        Box::new(Ticker {
            deadline: Some(base),
            fired: due.clone(),
        }),
    );
    dispatcher.register(
        ingress,
        Filter::default(),
        Box::new(Ticker {
            deadline: Some(base + Duration::from_secs(10)),
            fired: future.clone(),
        }),
    );

    // The dispatcher hands the reactor the soonest registration deadline.
    assert_eq!(dispatcher.next_deadline(), Some(base));

    // A sweep fires only the registration whose deadline has come due.
    dispatcher.on_deadline(base + Duration::from_secs(1), &mut reactor);
    assert_eq!(due.get(), 1, "the due handler is swept");
    assert_eq!(future.get(), 0, "the future handler is not");
    Ok(())
}

/// Registers a second recorder once, from inside its own call: the mid-route registration.
struct Registrar {
    ingress: CaptureKey,
    late: Rc<RefCell<Vec<Vec<u8>>>>,
    done: bool,
}

impl PacketHandler for Registrar {
    fn on_packet(
        &mut self,
        _: &Packet,
        dispatcher: &mut PacketDispatcher,
        _: &mut Reactor,
    ) -> Outcome {
        if !std::mem::replace(&mut self.done, true) {
            dispatcher.register(
                self.ingress,
                Filter::default(),
                Box::new(Recorder {
                    seen: self.late.clone(),
                }),
            );
        }
        Outcome::Filtered
    }
}

// route snapshots the live registration keys at the start, so a registration created during the
// call isn't in the snapshot and doesn't receive the in-flight frame. True whether it appends
// or reuses a freed slot (a key snapshot, unlike the old length bound, doesn't depend on index).
#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn a_mid_route_registration_is_not_fed_the_in_flight_frame() -> io::Result<()> {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new()?;
    let ingress = dispatcher.add_test_capture();
    let late = Rc::new(RefCell::new(Vec::new()));
    dispatcher.register(
        ingress,
        Filter::default(),
        Box::new(Registrar {
            ingress,
            late: late.clone(),
            done: false,
        }),
    );

    dispatcher.route(ingress, &probe_packet(b"x"), &mut reactor);
    assert!(
        late.borrow().is_empty(),
        "a registration born this route must not see the in-flight frame",
    );
    // It does receive the next frame.
    dispatcher.route(ingress, &probe_packet(b"y"), &mut reactor);
    assert_eq!(late.borrow().as_slice(), [b"y".to_vec()]);
    Ok(())
}

/// A reflector that re-enters the drain on its *own* ingress from inside the call.
/// The upstream take-out makes that nested drain return at its guard; were the
/// take-out removed, the nested drain would pull the next buffered frame and
/// re-route into this handler (which is taken out for the call), panicking the
/// `expect` in `route`.
struct Reentrant {
    ingress: CaptureKey,
    calls: Rc<RefCell<u32>>,
}

impl PacketHandler for Reentrant {
    fn on_packet(
        &mut self,
        _packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Outcome {
        *self.calls.borrow_mut() += 1;
        dispatcher.drain_and_route(self.ingress, reactor);
        Outcome::Filtered
    }
}

// Re-entrancy guard: a reflector re-entering the drain on its own ingress must hit
// the take-out guard, not re-route into its taken-out handler. Two probes are
// buffered so that, without the guard, the first packet's re-entrant drain pulls the
// second and panics `route`'s `expect`; with it, the outer loop handles both
// (calls == 2). Skips without capture access (no CAP_NET_RAW).
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn reentrant_drain_on_the_same_ingress_hits_the_guard() -> io::Result<()> {
    let _serial = loopback_lock();
    let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_reentrant")? else {
        return Ok(());
    };

    let (_receiver, target, sender) = probe_rig()?;

    let mut dispatcher = PacketDispatcher::new();
    let ingress = dispatcher.add_capture(ingress_cap)?;
    let calls = Rc::new(RefCell::new(0u32));
    dispatcher.register(
        ingress,
        Filter {
            dst_port: Some(target.port().into()),
            ..Filter::default()
        },
        Box::new(Reentrant {
            ingress,
            calls: calls.clone(),
        }),
    );

    let mut reactor = Reactor::new()?;
    sender.send_to(PROBE, target)?;
    sender.send_to(PROBE, target)?;
    // Let both probes land in the ring before the first drain, so the re-entrant
    // drain inside the first packet has the second frame available to mis-route.
    std::thread::sleep(Duration::from_millis(50));

    pump_until(
        2,
        || *calls.borrow() >= 2,
        || dispatcher.drain_and_route(ingress, &mut reactor),
    );

    assert_eq!(
        *calls.borrow(),
        2,
        "both probes should route via the outer drain; the re-entrant call must no-op"
    );
    Ok(())
}

/// A reflector that re-enters the drain on a *different* ingress: the case the same-ingress
/// take-out guard cannot see.
struct CrossDrainer {
    other: CaptureKey,
}

impl PacketHandler for CrossDrainer {
    fn on_packet(
        &mut self,
        _packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Outcome {
        dispatcher.drain_and_route(self.other, reactor);
        Outcome::Filtered
    }
}

// The cross-ingress re-drain slips past the take-out guard (the other capture is present, so
// its drain proceeds into `route`, which would rebuild the shared `route_keys` scratch under
// the outer loop); the entry assert must catch it. Both loopback captures see the one probe.
// `should_panic` can't express the no-privilege skip, so the panic is caught by hand. Skips
// without capture access.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "route's re-entry guard is a debug_assert!, compiled out in release"
)]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn reentrant_drain_on_another_ingress_trips_the_assert() -> io::Result<()> {
    let _serial = loopback_lock();
    let Some(cap_a) = open_or_skip(LOOPBACK_IFACE, "dispatch_cross_a")? else {
        return Ok(());
    };
    let Some(cap_b) = open_or_skip(LOOPBACK_IFACE, "dispatch_cross_b")? else {
        return Ok(());
    };

    let (_receiver, target, sender) = probe_rig()?;

    let mut dispatcher = PacketDispatcher::new();
    let a = dispatcher.add_capture(cap_a)?;
    let b = dispatcher.add_capture(cap_b)?;
    dispatcher.register(
        a,
        Filter {
            dst_port: Some(target.port().into()),
            ..Filter::default()
        },
        Box::new(CrossDrainer { other: b }),
    );

    let mut reactor = Reactor::new()?;
    sender.send_to(PROBE, target)?;

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pump_until(
            1,
            || false, // no success condition: the only exit is the assert firing
            || dispatcher.drain_and_route(a, &mut reactor),
        );
    }))
    .expect_err("a cross-ingress re-drain must trip route's re-entry assert");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        message.contains("route re-entered"),
        "unexpected panic message: {message}"
    );
    Ok(())
}

// End-to-end through the reactor: register the dispatcher itself as a handler watching
// its capture fds, then let `poll_once` drive it. A looped UDP probe makes the ingress
// capture readable; the reactor names that exact fd, the dispatcher maps it back to the
// capture, drains it, and routes to the Echo, which re-emits on the egress key.
// Exercises the per-fd `on_readable`. Skips without capture access (no CAP_NET_RAW).
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn reactor_drives_the_dispatcher_to_route_a_packet() -> io::Result<()> {
    let _serial = loopback_lock();
    let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_reactor_in")? else {
        return Ok(());
    };
    let Some(egress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_reactor_eg")? else {
        return Ok(());
    };

    let (_receiver, target, sender) = probe_rig()?;

    let mut dispatcher = PacketDispatcher::new();
    let ingress = dispatcher.add_capture(ingress_cap)?;
    let egress = dispatcher.add_capture(egress_cap)?;
    let seen = Rc::new(RefCell::new(Vec::new()));
    dispatcher.register(
        ingress,
        Filter {
            dst_port: Some(target.port().into()),
            ..Filter::default()
        },
        Box::new(Echo {
            egress,
            seen: seen.clone(),
        }),
    );

    let mut reactor = Reactor::new()?;
    let watches = dispatcher.capture_watches();
    reactor.register_with_fds(Box::new(dispatcher), &watches)?;

    sender.send_to(PROBE, target)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while seen.borrow().is_empty() && Instant::now() < deadline {
        reactor.poll_once(Some(Duration::from_millis(100)))?;
    }

    let records = seen.borrow();
    assert!(
        !records.is_empty(),
        "the reflector never fired via the reactor"
    );
    assert_eq!(records[0].0, PROBE, "reflector saw the wrong payload");
    assert!(records[0].1, "the keyed egress send failed");
    Ok(())
}

// Privilege-free: a fresh dispatcher has no captures, so an out-of-range key stands in
// for a forged reactor `user_data`. The drain guard, `egress_addrs`, `link_type`, `send`,
// and `send_udp_group` must each be a safe no-op (log-drop / `None` / `Ok`), never a panic:
// the new behavior the capture-gated e2e tests above skip without `CAP_NET_RAW`.
#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn unknown_capture_key_is_a_safe_no_op() -> io::Result<()> {
    let mut dispatcher = PacketDispatcher::new();
    let mut reactor = Reactor::new()?;
    let bogus = CaptureKey::from_u64(999);
    dispatcher.drain_and_route(bogus, &mut reactor); // out-of-range guard arm, no panic
    assert!(dispatcher.egress_addrs(bogus).is_none());
    assert!(dispatcher.link_type(bogus).is_none());
    assert!(dispatcher.send(bogus, b"x").is_ok());
    // send_udp_group on an unknown egress is the same logged drop, not a build attempt.
    let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
    assert!(
        dispatcher
            .send_udp_group(bogus, dst, DatagramSource::Egress { port: 1 }, 64, b"x")
            .is_ok()
    );
    Ok(())
}

/// The mid-drain probe's recording: the v4 it resolved for the ingress while drained,
/// and whether the send to the taken-out ingress returned `Ok`.
type ProbeResult = Rc<RefCell<Option<(Option<Ipv4Addr>, bool)>>>;

/// Probes the take-out invariants from inside the drain: while its ingress capture is
/// taken out, the interface link stays resident (so `egress_addrs` resolves) and a send
/// to the taken-out capture is a logged drop (`Ok`), not a panic.
struct MidDrainProbe {
    ingress: CaptureKey,
    result: ProbeResult,
}

impl PacketHandler for MidDrainProbe {
    fn on_packet(
        &mut self,
        _packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) -> Outcome {
        let addrs = dispatcher
            .egress_addrs(self.ingress)
            .and_then(InterfaceAddresses::v4);
        let sent_ok = dispatcher.send(self.ingress, b"x").is_ok();
        *self.result.borrow_mut() = Some((addrs, sent_ok));
        Outcome::Filtered
    }
}

// The wrapper design's headline invariant: the take-out clears only the inner capture,
// leaving the interface link resident, so `egress_addrs(ingress)` still resolves while
// the capture is drained, and `send(ingress)` drops (`Ok`) rather than panicking. Both
// are checked from inside the reflector's call, when the ingress entry's capture is
// `None`. Skips without capture access (no CAP_NET_RAW).
#[test]
#[cfg_attr(miri, ignore = "needs a real capture device")]
fn ingress_resolves_and_drops_while_taken_out() -> io::Result<()> {
    let _serial = loopback_lock();
    let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_mid_drain")? else {
        return Ok(());
    };

    let (_receiver, target, sender) = probe_rig()?;

    let mut dispatcher = PacketDispatcher::new();
    let ingress = dispatcher.add_capture(ingress_cap)?;
    let result = Rc::new(RefCell::new(None));
    dispatcher.register(
        ingress,
        Filter {
            dst_port: Some(target.port().into()),
            ..Filter::default()
        },
        Box::new(MidDrainProbe {
            ingress,
            result: result.clone(),
        }),
    );

    let mut reactor = Reactor::new()?;
    sender.send_to(PROBE, target)?;
    pump_until(
        2,
        || result.borrow().is_some(),
        || dispatcher.drain_and_route(ingress, &mut reactor),
    );

    let recorded = *result.borrow();
    let (addrs, sent_ok) = recorded.expect("the probe never fired");
    assert_eq!(
        addrs,
        Some(Ipv4Addr::LOCALHOST),
        "ingress addresses must resolve while the capture is taken out"
    );
    assert!(
        sent_ok,
        "send to the taken-out ingress must drop (Ok), not panic"
    );
    Ok(())
}

// new() opens the routing socket; its fd joins the watch list under the sentinel tag,
// distinct from any capture key. Best-effort: the watch appears only if the socket opened
// (some sandboxes deny it), so an empty watch list means skip.
#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn monitor_fd_is_watched_under_the_sentinel_tag() {
    let dispatcher = PacketDispatcher::new();
    let watches = dispatcher.capture_watches();
    if watches.is_empty() {
        eprintln!("skip: the routing socket could not be opened in this environment");
        return;
    }
    // No captures were added, so the monitor fd is the sole watch, under MONITOR_TAG.
    assert_eq!(watches.len(), 1, "only the monitor fd should be watched");
    assert_eq!(
        watches[0].1, MONITOR_TAG,
        "the monitor fd must carry MONITOR_TAG"
    );
}

// A join_group on an unknown capture is logged and skipped, not an error or a panic.
#[test]
#[cfg_attr(miri, ignore = "needs a real socket")]
fn join_group_ignores_an_unknown_capture() {
    let mut dispatcher = PacketDispatcher::new();
    let group = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
    assert!(dispatcher.join_group(CaptureKey(9999), group).is_ok());
}
