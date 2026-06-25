//! The Wake-on-LAN reflector: re-broadcasts magic packets seen on the source interface onto
//! the target interface, so a wake sent on one link reaches a sleeping device on another.
//!
//! A magic packet is 6 bytes of `0xFF` followed by the target device's MAC repeated 16 times
//! (102 bytes); a trailing `SecureOn` password, if present, is forwarded verbatim. The reflector
//! validates the payload, then re-emits it on the target interface as a v4 limited broadcast /
//! v6 link-local all-nodes multicast, sourced from that interface's own address (the handler
//! and `build`, which wire this into the dispatcher, land with the next steps).

use crate::net::mac::MacAddr;

/// The all-ones prefix that opens a magic packet.
const PREFIX_LEN: usize = 6;
/// A MAC address is six bytes.
const MAC_LEN: usize = 6;
/// The target MAC repeats this many times after the prefix.
const MAC_REPS: usize = 16;
/// The smallest valid magic packet: the prefix plus the 16 MAC repetitions.
const MAGIC_LEN: usize = PREFIX_LEN + MAC_REPS * MAC_LEN;

/// Whether `payload` opens with a Wake-on-LAN magic packet for an acceptable target: the
/// `6×0xFF` prefix followed by one MAC repeated 16 times. Trailing bytes (a `SecureOn` password)
/// are ignored — only the leading [`MAGIC_LEN`] are inspected — and the caller forwards them
/// as-is. When `target_mac` is set, the repeated MAC must equal it, so only that one device's
/// wakes are relayed.
fn is_magic_packet(payload: &[u8], target_mac: Option<MacAddr>) -> bool {
    let Some(magic) = payload.get(..MAGIC_LEN) else {
        return false;
    };
    if magic[..PREFIX_LEN] != [0xff; PREFIX_LEN] {
        return false;
    }
    let mac = &magic[PREFIX_LEN..PREFIX_LEN + MAC_LEN];
    // The other 15 repetitions must all equal the first.
    if !magic[PREFIX_LEN + MAC_LEN..]
        .chunks_exact(MAC_LEN)
        .all(|rep| rep == mac)
    {
        return false;
    }
    // A configured target narrows the reflector to that device's wake.
    target_mac.is_none_or(|target| mac == target.octets())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

    /// A well-formed magic packet for `mac`, plus optional `trailer` (`SecureOn`) bytes.
    fn magic_packet(mac: [u8; 6], trailer: &[u8]) -> Vec<u8> {
        let mut p = vec![0xff; PREFIX_LEN];
        for _ in 0..MAC_REPS {
            p.extend_from_slice(&mac);
        }
        p.extend_from_slice(trailer);
        p
    }

    #[test]
    fn accepts_any_device_when_unfiltered() {
        assert!(is_magic_packet(&magic_packet(DEVICE, &[]), None));
    }

    #[test]
    fn accepts_a_secureon_trailer() {
        // Bytes past the 102 are a SecureOn password: ignored here, forwarded by the caller.
        let packet = magic_packet(DEVICE, &[0xde, 0xad, 0xbe, 0xef]);
        assert!(is_magic_packet(&packet, None));
    }

    #[test]
    fn filters_to_the_configured_device() {
        let packet = magic_packet(DEVICE, &[]);
        assert!(is_magic_packet(&packet, Some(MacAddr::from(DEVICE))));
        assert!(!is_magic_packet(&packet, Some(MacAddr::from([0xaa; 6]))));
    }

    #[test]
    fn rejects_a_short_payload() {
        let packet = magic_packet(DEVICE, &[]);
        assert!(!is_magic_packet(&packet[..MAGIC_LEN - 1], None));
        assert!(!is_magic_packet(&[], None));
    }

    #[test]
    fn rejects_a_broken_prefix() {
        let mut packet = magic_packet(DEVICE, &[]);
        packet[0] = 0xfe;
        assert!(!is_magic_packet(&packet, None));
    }

    #[test]
    fn rejects_inconsistent_repetitions() {
        let mut packet = magic_packet(DEVICE, &[]);
        // Corrupt the 7th repetition so it no longer matches the first.
        packet[PREFIX_LEN + 6 * MAC_LEN] ^= 0xff;
        assert!(!is_magic_packet(&packet, None));
    }
}
