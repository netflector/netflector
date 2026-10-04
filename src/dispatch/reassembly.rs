//! Reassembly of fragmented UDP datagrams ahead of routing: a few slots, each collecting one
//! datagram's fragments into a reused buffer, and apart from them a list of datagrams whose
//! remaining fragments are dropped. Any overlap abandons the datagram, as RFC 8200 requires for
//! IPv6; IPv4 gets the same rule.

use std::net::IpAddr;
use std::time::{Duration, Instant};
use std::vec;

use crate::linear_map::LinearMap;
use crate::net::FRAGMENT_UNIT;
use crate::net::packet::{Fragment, FragmentHeader, Packet, ParseError};

use super::CaptureKey;

/// Datagrams collected at once.
const SLOTS: usize = 16;

/// Datagrams remembered as unwanted or given up on; an entry holds no buffer.
const DISCARDS: usize = 64;

/// The most UDP header and payload a datagram reassembles to: RFC 6762's ceiling for an mDNS
/// packet, which also clears DPWS's 4096-byte limit on a WSD envelope.
pub(super) const MAX_DATAGRAM_LEN: usize = 9000;

/// A one-hop datagram's fragments arrive back to back; one this late is lost.
const EXPIRY: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DatagramKey {
    ingress: CaptureKey,
    source: IpAddr,
    dest: IpAddr,
    id: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Loss {
    /// A fragment reached `end` bytes, past [`MAX_DATAGRAM_LEN`].
    TooLarge {
        end: usize,
    },
    /// Fragments overlapped, or disagreed on where the datagram ends.
    Inconsistent,
    /// A fragment before the last whose length isn't a whole number of [`FRAGMENT_UNIT`]s, or a
    /// first one too short for the UDP header.
    Malformed,
    Expired,
    /// Its slot went to a newer datagram.
    Evicted,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Lost {
    pub(super) ingress: CaptureKey,
    pub(super) source: IpAddr,
    pub(super) dest: IpAddr,
    pub(super) loss: Loss,
}

impl Lost {
    fn new(key: DatagramKey, loss: Loss) -> Self {
        Self {
            ingress: key.ingress,
            source: key.source,
            dest: key.dest,
            loss,
        }
    }
}

const BLOCKS: usize = MAX_DATAGRAM_LEN.div_ceil(FRAGMENT_UNIT);

/// One datagram's bytes and which [`FRAGMENT_UNIT`]s of them have arrived, reused across
/// datagrams.
struct Buffer {
    bytes: [u8; MAX_DATAGRAM_LEN],
    received: [bool; BLOCKS],
}

impl Buffer {
    fn new() -> Box<Self> {
        Box::new(Self {
            bytes: [0; MAX_DATAGRAM_LEN],
            received: [false; BLOCKS],
        })
    }
}

/// A complete datagram in a buffer on loan until [`Reassembler::recycle`].
pub(super) struct Reassembled {
    first: FragmentHeader,
    buf: Box<Buffer>,
    len: usize,
}

impl Reassembled {
    /// # Errors
    /// As [`Packet::reassembled`].
    pub(super) fn packet(&self) -> Result<Packet<'_>, ParseError> {
        Packet::reassembled(&self.first, &self.buf.bytes[..self.len])
    }
}

struct Collecting {
    buf: Box<Buffer>,
    started: Instant,
    /// Known once the last fragment arrives.
    len: Option<usize>,
    first: Option<FragmentHeader>,
}

impl Collecting {
    fn new(mut buf: Box<Buffer>, started: Instant) -> Self {
        buf.received.fill(false);
        Self {
            buf,
            started,
            len: None,
            first: None,
        }
    }

    fn add(&mut self, fragment: &Fragment<'_>) -> Result<(), Loss> {
        let FragmentHeader { offset, more, .. } = fragment.header;
        let data = fragment.data;
        let end = offset + data.len();
        if (more && !data.len().is_multiple_of(FRAGMENT_UNIT))
            || (offset == 0 && fragment.headers().is_none())
        {
            return Err(Loss::Malformed);
        }
        if end > MAX_DATAGRAM_LEN {
            return Err(Loss::TooLarge { end });
        }
        let blocks = offset / FRAGMENT_UNIT..end.div_ceil(FRAGMENT_UNIT);
        let ends_elsewhere = match self.len {
            Some(len) if more => end > len,
            Some(len) => end != len,
            None => !more && self.buf.received[blocks.end..].contains(&true),
        };
        if ends_elsewhere || self.buf.received[blocks.clone()].contains(&true) {
            return Err(Loss::Inconsistent);
        }
        self.buf.bytes[offset..end].copy_from_slice(data);
        self.buf.received[blocks].fill(true);
        if !more {
            self.len = Some(end);
        }
        if offset == 0 {
            self.first = Some(fragment.header);
        }
        Ok(())
    }

    /// The first fragment is in and every unit up to the end has arrived.
    fn is_complete(&self) -> bool {
        self.first.is_some()
            && self.len.is_some_and(|len| {
                self.buf.received[..len.div_ceil(FRAGMENT_UNIT)]
                    .iter()
                    .all(|&got| got)
            })
    }

    /// `None` while any fragment is missing.
    fn finish(self) -> Option<Reassembled> {
        if !self.is_complete() {
            return None;
        }
        Some(Reassembled {
            first: self.first?,
            len: self.len?,
            buf: self.buf,
        })
    }
}

pub(super) struct Reassembler {
    collecting: LinearMap<DatagramKey, Collecting>,
    /// Datagrams whose remaining fragments are dropped uncopied, and since when.
    discarding: LinearMap<DatagramKey, Instant>,
    /// Buffers no slot holds, kept for the next.
    spare: Vec<Box<Buffer>>,
    lost: Vec<Lost>,
}

impl Reassembler {
    pub(super) fn new() -> Self {
        Self {
            collecting: LinearMap::new(),
            discarding: LinearMap::new(),
            spare: Vec::new(),
            lost: Vec::new(),
        }
    }

    /// `Some` once `fragment` completes its datagram. A first fragment not `wanted`, one no
    /// registration would route, drops the rest of its datagram uncopied. Losses, of this datagram
    /// or of others it displaced or outlived, queue for [`drain_lost`](Self::drain_lost).
    pub(super) fn offer(
        &mut self,
        ingress: CaptureKey,
        fragment: &Fragment<'_>,
        wanted: bool,
        now: Instant,
    ) -> Option<Reassembled> {
        self.expire(now);
        let key = DatagramKey {
            ingress,
            source: fragment.header.source,
            dest: fragment.header.dest,
            id: fragment.header.id,
        };
        if self.discarding.get(&key).is_some() {
            return None;
        }
        if !wanted {
            if let Some(collecting) = self.collecting.remove(&key) {
                self.spare.push(collecting.buf);
            }
            self.discard(key, now);
            return None;
        }
        if self.collecting.get(&key).is_none() {
            self.make_room(now);
            let buf = self.spare.pop().unwrap_or_else(Buffer::new);
            self.collecting.insert(key, Collecting::new(buf, now));
        }
        let collecting = self.collecting.get_mut(&key)?;
        if let Err(loss) = collecting.add(fragment) {
            self.give_up(key, loss, now);
            return None;
        }
        if !collecting.is_complete() {
            return None;
        }
        self.collecting.remove(&key)?.finish()
    }

    pub(super) fn recycle(&mut self, done: Reassembled) {
        self.spare.push(done.buf);
    }

    pub(super) fn drain_lost(&mut self) -> vec::Drain<'_, Lost> {
        self.lost.drain(..)
    }

    fn make_room(&mut self, now: Instant) {
        if self.collecting.len() >= SLOTS
            && let Some(oldest) = self
                .collecting
                .iter()
                .min_by_key(|(_, collecting)| collecting.started)
                .map(|(key, _)| *key)
        {
            self.give_up(oldest, Loss::Evicted, now);
        }
    }

    /// The datagram's later fragments are discarded, not collected again.
    fn give_up(&mut self, key: DatagramKey, loss: Loss, now: Instant) {
        if let Some(collecting) = self.collecting.remove(&key) {
            self.spare.push(collecting.buf);
            self.lost.push(Lost::new(key, loss));
        }
        self.discard(key, now);
    }

    /// At capacity the oldest entry is forgotten.
    fn discard(&mut self, key: DatagramKey, now: Instant) {
        if self.discarding.len() >= DISCARDS
            && let Some(oldest) = self
                .discarding
                .iter()
                .min_by_key(|(_, since)| **since)
                .map(|(key, _)| *key)
        {
            self.discarding.remove(&oldest);
        }
        self.discarding.insert(key, now);
    }

    fn expire(&mut self, now: Instant) {
        self.discarding
            .retain(|_, since| now.duration_since(*since) < EXPIRY);
        while let Some(key) = self.first_expired(now) {
            self.give_up(key, Loss::Expired, now);
        }
    }

    fn first_expired(&self, now: Instant) -> Option<DatagramKey> {
        self.collecting
            .iter()
            .find(|(_, collecting)| now.duration_since(collecting.started) >= EXPIRY)
            .map(|(key, _)| *key)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::ops::Range;

    use super::*;
    use crate::net::LinkType;
    use crate::net::frame::{LinkHeader, UdpFrames};
    use crate::net::mac::MacAddr;
    use crate::net::packet::Parsed;

    const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 70, 70);
    const DEST: Ipv4Addr = Ipv4Addr::new(10, 0, 70, 1);

    fn ingress() -> CaptureKey {
        CaptureKey::from_u64(0)
    }

    /// The UDP header and payload of a valid IPv4 datagram of `len` payload bytes: what reassembly
    /// must put back together.
    fn datagram(len: usize) -> Vec<u8> {
        let payload: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let link = LinkHeader::Ethernet {
            dst: MacAddr::broadcast(),
            src: MacAddr::broadcast(),
        };
        let src = SocketAddrV4::new(SOURCE, 3702);
        let dst = SocketAddrV4::new(DEST, 40000);
        let frames = UdpFrames::ipv4(link, src, dst, 64, 0, &payload, usize::MAX).unwrap();
        let mut frame = vec![0u8; 1 << 16];
        let n = frames.write(0, &mut frame).unwrap();
        frame[14 + 20..n].to_vec()
    }

    /// The fragment of datagram `id` carrying `datagram[range]`.
    fn piece(datagram: &[u8], id: u32, range: Range<usize>) -> Fragment<'_> {
        Fragment {
            header: FragmentHeader {
                source: IpAddr::V4(SOURCE),
                dest: IpAddr::V4(DEST),
                id,
                offset: range.start,
                more: range.end < datagram.len(),
                ttl: 64,
                dst_mac: None,
                src_mac: None,
            },
            data: &datagram[range],
        }
    }

    /// Offer each fragment in turn, wanted, at `now`; what the last one completed.
    fn offer_all(
        reassembler: &mut Reassembler,
        fragments: &[Fragment<'_>],
        now: Instant,
    ) -> Option<Reassembled> {
        let mut done = None;
        for fragment in fragments {
            assert!(done.is_none(), "completed before its last fragment");
            done = reassembler.offer(ingress(), fragment, true, now);
        }
        done
    }

    fn lost(reassembler: &mut Reassembler) -> Vec<Loss> {
        reassembler.drain_lost().map(|lost| lost.loss).collect()
    }

    #[test]
    fn reassembles_fragments_in_any_order() {
        let datagram = datagram(2595);
        let pieces = [
            piece(&datagram, 1, 0..1000),
            piece(&datagram, 1, 1000..2000),
            piece(&datagram, 1, 2000..datagram.len()),
        ];
        let now = Instant::now();
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut reassembler = Reassembler::new();
            let fragments = order.map(|i| pieces[i]);
            let done = offer_all(&mut reassembler, &fragments, now).expect("complete");
            let packet = done.packet().unwrap();
            assert_eq!(packet.source, "10.0.70.70:3702".parse().unwrap());
            assert_eq!(packet.dest, "10.0.70.1:40000".parse().unwrap());
            assert_eq!(packet.payload, &datagram[8..]);
            assert_eq!(lost(&mut reassembler), []);
            reassembler.recycle(done);
            assert_eq!(reassembler.collecting.len(), 0);
            assert_eq!(reassembler.spare.len(), 1);
        }
    }

    #[test]
    fn a_datagram_with_a_gap_does_not_finish() {
        let datagram = datagram(200);
        let collect = |ranges: &[Range<usize>]| {
            let mut collecting = Collecting::new(Buffer::new(), Instant::now());
            for range in ranges {
                collecting.add(&piece(&datagram, 1, range.clone())).unwrap();
            }
            collecting
        };
        // The first and the last fragment are in, the middle is missing.
        assert!(collect(&[0..96, 192..208]).finish().is_none());
        assert!(collect(&[0..96, 192..208, 96..192]).finish().is_some());
    }

    #[test]
    fn an_ipv6_datagram_reassembles_too() {
        let payload = [0x6a; 100];
        let link = LinkHeader::Ethernet {
            dst: MacAddr::broadcast(),
            src: MacAddr::broadcast(),
        };
        let src = SocketAddrV6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 3702, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2), 40000, 0, 0);
        let frames = UdpFrames::ipv6(link, src, dst, 1, 9, &payload, 104).unwrap();
        let written: Vec<Vec<u8>> = (0..frames.count())
            .map(|index| {
                let mut frame = vec![0u8; 2048];
                let n = frames.write(index, &mut frame).unwrap();
                frame.truncate(n);
                frame
            })
            .collect();
        let mut reassembler = Reassembler::new();
        let mut done = None;
        for frame in &written {
            let Ok(Parsed::Fragment(fragment)) = Parsed::parse(LinkType::Ethernet, frame) else {
                panic!("not a fragment");
            };
            done = reassembler.offer(ingress(), &fragment, true, Instant::now());
        }
        let done = done.expect("complete");
        let packet = done.packet().unwrap();
        assert_eq!(packet.source, SocketAddr::V6(src));
        assert_eq!(packet.payload, payload);
    }

    #[test]
    fn an_overlap_or_a_duplicate_abandons_the_datagram() {
        let datagram = datagram(200);
        let now = Instant::now();
        for second in [8..16, 0..16] {
            let mut reassembler = Reassembler::new();
            let fragments = [piece(&datagram, 1, 0..16), piece(&datagram, 1, second)];
            assert!(offer_all(&mut reassembler, &fragments, now).is_none());
            assert_eq!(lost(&mut reassembler), [Loss::Inconsistent]);
            // The rest is swallowed, not collected again.
            let rest = piece(&datagram, 1, 16..datagram.len());
            assert!(reassembler.offer(ingress(), &rest, true, now).is_none());
            assert_eq!(lost(&mut reassembler), []);
            assert_eq!(reassembler.collecting.len(), 0);
        }
    }

    #[test]
    fn fragments_disagreeing_on_the_end_abandon_the_datagram() {
        let datagram = datagram(200);
        let mut ending = piece(&datagram, 1, 96..200);
        ending.header.more = false;
        let mut past_it = piece(&datagram, 1, 200..datagram.len());
        past_it.header.more = true;
        for fragments in [[ending, past_it], [past_it, ending]] {
            let mut reassembler = Reassembler::new();
            assert!(offer_all(&mut reassembler, &fragments, Instant::now()).is_none());
            assert_eq!(lost(&mut reassembler), [Loss::Inconsistent]);
        }
    }

    #[test]
    fn a_datagram_past_the_limit_is_dropped() {
        let datagram = datagram(MAX_DATAGRAM_LEN + 100);
        let mut reassembler = Reassembler::new();
        let first = piece(&datagram, 1, 0..1480);
        assert!(
            reassembler
                .offer(ingress(), &first, true, Instant::now())
                .is_none()
        );
        let past = piece(&datagram, 1, 8880..datagram.len());
        assert!(
            reassembler
                .offer(ingress(), &past, true, Instant::now())
                .is_none()
        );
        assert_eq!(
            lost(&mut reassembler),
            [Loss::TooLarge {
                end: datagram.len()
            }]
        );
    }

    #[test]
    fn a_misaligned_or_headless_fragment_is_malformed() {
        let datagram = datagram(200);
        let now = Instant::now();
        // A middle fragment of 12 bytes, and a first one of 4: no room for the UDP header.
        for fragment in [piece(&datagram, 1, 16..28), {
            let mut first = piece(&datagram, 2, 0..4);
            first.header.more = true;
            first
        }] {
            let mut reassembler = Reassembler::new();
            assert!(reassembler.offer(ingress(), &fragment, true, now).is_none());
            assert_eq!(lost(&mut reassembler), [Loss::Malformed]);
        }
    }

    #[test]
    fn an_unwanted_datagram_is_dropped_without_a_buffer() {
        let datagram = datagram(200);
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        let first = piece(&datagram, 1, 0..96);
        assert!(reassembler.offer(ingress(), &first, false, now).is_none());
        let rest = piece(&datagram, 1, 96..datagram.len());
        assert!(reassembler.offer(ingress(), &rest, true, now).is_none());
        assert_eq!(lost(&mut reassembler), []);
        assert_eq!(reassembler.spare.len(), 0);
        // A fragment ahead of its unwanted first one releases its buffer quietly.
        let mut reassembler = Reassembler::new();
        let rest = piece(&datagram, 2, 96..datagram.len());
        assert!(reassembler.offer(ingress(), &rest, true, now).is_none());
        let first = piece(&datagram, 2, 0..96);
        assert!(reassembler.offer(ingress(), &first, false, now).is_none());
        assert_eq!(lost(&mut reassembler), []);
        assert_eq!(reassembler.spare.len(), 1);
    }

    #[test]
    fn a_stalled_datagram_expires() {
        let datagram = datagram(200);
        let start = Instant::now();
        let mut reassembler = Reassembler::new();
        let first = piece(&datagram, 1, 0..96);
        assert!(reassembler.offer(ingress(), &first, true, start).is_none());
        let other = piece(&datagram, 2, 0..96);
        let later = start + EXPIRY.saturating_sub(Duration::from_millis(1));
        assert!(reassembler.offer(ingress(), &other, true, later).is_none());
        assert_eq!(lost(&mut reassembler), []);
        // Datagram 1's rest, too late: it expired first, and the rest is discarded.
        let rest = piece(&datagram, 1, 96..datagram.len());
        assert!(
            reassembler
                .offer(ingress(), &rest, true, start + EXPIRY)
                .is_none()
        );
        assert_eq!(lost(&mut reassembler), [Loss::Expired]);
        assert_eq!(reassembler.collecting.len(), 1);
    }

    #[test]
    fn unwanted_datagrams_never_take_a_collecting_slot() {
        let datagram = datagram(200);
        let now = Instant::now();
        let first = |id| piece(&datagram, id, 0..96);
        let slots = u32::try_from(SLOTS).unwrap();
        let discards = u32::try_from(DISCARDS).unwrap();
        let mut reassembler = Reassembler::new();
        for id in 0..slots {
            assert!(
                reassembler
                    .offer(ingress(), &first(id), true, now)
                    .is_none()
            );
        }
        for id in slots..slots + 2 * discards {
            assert!(
                reassembler
                    .offer(ingress(), &first(id), false, now)
                    .is_none()
            );
        }
        assert_eq!(lost(&mut reassembler), []);
        assert_eq!(reassembler.collecting.len(), SLOTS);
        assert!(reassembler.collecting.iter().all(|(key, _)| key.id < slots));
    }

    #[test]
    fn a_full_table_evicts_its_oldest_datagram() {
        let datagram = datagram(200);
        let start = Instant::now();
        let first = |id| piece(&datagram, id, 0..96);
        let slots = u32::try_from(SLOTS).unwrap();
        let mut reassembler = Reassembler::new();
        for id in 0..=slots {
            let at = start + Duration::from_millis(u64::from(id));
            assert!(reassembler.offer(ingress(), &first(id), true, at).is_none());
        }
        let evicted: Vec<_> = reassembler.drain_lost().collect();
        assert_eq!(
            evicted,
            [Lost {
                ingress: ingress(),
                source: IpAddr::V4(SOURCE),
                dest: IpAddr::V4(DEST),
                loss: Loss::Evicted,
            }]
        );
        assert!(reassembler.collecting.iter().all(|(key, _)| key.id != 0));
        // The evicted datagram's rest is discarded, not collected again.
        let rest = piece(&datagram, 0, 96..datagram.len());
        assert!(reassembler.offer(ingress(), &rest, true, start).is_none());
        assert_eq!(lost(&mut reassembler), []);
        assert_eq!(reassembler.collecting.len(), SLOTS);
    }

    #[test]
    fn a_full_discard_list_forgets_its_oldest() {
        let datagram = datagram(200);
        let start = Instant::now();
        let discards = u32::try_from(DISCARDS).unwrap();
        let mut reassembler = Reassembler::new();
        for id in 0..=discards {
            let at = start + Duration::from_millis(u64::from(id));
            let first = piece(&datagram, id, 0..96);
            assert!(reassembler.offer(ingress(), &first, false, at).is_none());
        }
        assert_eq!(reassembler.discarding.len(), DISCARDS);
        // Forgotten, datagram 0's rest looks like a new datagram.
        let rest = piece(&datagram, 0, 96..datagram.len());
        assert!(reassembler.offer(ingress(), &rest, true, start).is_none());
        assert_eq!(reassembler.collecting.len(), 1);
    }

    #[test]
    fn interfaces_keep_their_datagrams_apart() {
        let datagram = datagram(200);
        let now = Instant::now();
        let other = CaptureKey::from_u64(1);
        let mut reassembler = Reassembler::new();
        let first = piece(&datagram, 1, 0..96);
        assert!(reassembler.offer(ingress(), &first, true, now).is_none());
        let rest = piece(&datagram, 1, 96..datagram.len());
        assert!(reassembler.offer(other, &rest, true, now).is_none());
        assert!(reassembler.offer(ingress(), &rest, true, now).is_some());
    }

    #[test]
    fn a_corrupted_datagram_fails_its_checksum() {
        let mut datagram = datagram(200);
        datagram[100] ^= 0xff;
        let fragments = [piece(&datagram, 1, 0..96), piece(&datagram, 1, 96..208)];
        let mut reassembler = Reassembler::new();
        let done = offer_all(&mut reassembler, &fragments, Instant::now()).expect("complete");
        assert_eq!(done.packet(), Err(ParseError::BadChecksum));
    }
}
