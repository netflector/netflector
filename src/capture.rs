//! Raw L2 packet capture: a per-interface handle the reactor can poll.
//!
//! One backend per platform behind a uniform `Capture`: BPF on macOS/FreeBSD,
//! `AF_PACKET` on Linux. The handle owns a pollable fd, reads link-layer frames
//! into a reused buffer (no per-frame allocation), and injects built frames.

mod filter;

#[cfg(target_os = "linux")]
mod af_packet;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bpf;

/// The platform `Capture` under one name, so consumers and tests need not name the backend.
#[cfg(target_os = "linux")]
pub(crate) use self::af_packet::Capture;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) use self::bpf::Capture;

/// One read of a capture.
#[derive(Debug)]
pub(crate) enum Read<'a> {
    Frame(&'a [u8]),
    /// A frame too large to forward, dropped and counted.
    Oversized,
}

/// Open a capture on `if_name`, returning `Ok(None)` (and noting why) when the host
/// can't: no BPF access / `CAP_NET_RAW`, or the interface is absent. Other errors
/// propagate for the caller to `?`.
#[cfg(test)]
pub(crate) fn open_or_skip(if_name: &str, what: &str) -> std::io::Result<Option<Capture>> {
    match Capture::open(if_name) {
        Ok(capture) => Ok(Some(capture)),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            ) || e.raw_os_error() == Some(libc::EACCES)
                || e.raw_os_error() == Some(libc::EPERM) =>
        {
            eprintln!("skip {what}: cannot capture on {if_name} ({e})");
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// The tests that open a capture on the loopback interface hold this for their duration: every
/// descriptor attached there sees every frame, and the kernel's small double buffer drops what
/// a concurrent test's traffic leaves no room for.
#[cfg(test)]
pub(crate) fn loopback_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A tun device attached to this process: its kernel side is a raw IP link, `far_end` the other
/// side, where a packet written arrives on the link and one sent on the link comes out. Gone
/// when the file closes. For the raw IP link tests.
#[cfg(all(test, target_os = "linux"))]
pub(crate) struct Tun {
    pub(crate) far_end: std::fs::File,
    pub(crate) name: String,
}

#[cfg(all(test, target_os = "linux"))]
impl Tun {
    /// `None`, with a note, where the test can't run: no root, no `/dev/net/tun`, or a kernel
    /// (user-mode QEMU) that refuses the attach.
    pub(crate) fn create() -> Option<Self> {
        use std::os::fd::AsRawFd;

        // A `%d` template asks for a kernel-assigned name, written back by the ioctl.
        const TEMPLATE: &[u8] = b"nftun%d";
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skip tun test: creating a tun device requires root");
            return None;
        }
        let far_end = match std::fs::File::options()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
        {
            Ok(file) => file,
            Err(e) => {
                eprintln!("skip tun test: /dev/net/tun: {e}");
                return None;
            }
        };
        // SAFETY: an all-zero `ifreq` is valid (a zeroed name and union).
        let mut ifr: libc::ifreq = unsafe { core::mem::zeroed() };
        // SAFETY: the template fits `ifr_name` with the terminator the zeroed `ifr` provides.
        unsafe {
            std::ptr::copy_nonoverlapping(
                TEMPLATE.as_ptr(),
                ifr.ifr_name.as_mut_ptr().cast::<u8>(),
                TEMPLATE.len(),
            );
        }
        ifr.ifr_ifru.ifru_flags =
            libc::c_short::try_from(libc::IFF_TUN | libc::IFF_NO_PI).expect("tun flags fit");
        // SAFETY: TUNSETIFF reads the flags and name template, and writes the name back.
        if unsafe { libc::ioctl(far_end.as_raw_fd(), libc::TUNSETIFF, &raw mut ifr) } < 0 {
            eprintln!(
                "skip tun test: TUNSETIFF: {}",
                std::io::Error::last_os_error()
            );
            return None;
        }
        // SAFETY: the kernel wrote a NUL-terminated name into `ifr_name`.
        let name = unsafe { std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let up = std::process::Command::new("ip")
            .args(["link", "set", "dev", &name, "up"])
            .status()
            .is_ok_and(|status| status.success());
        if !up {
            eprintln!("skip tun test: cannot bring {name} up (no ip(8)?)");
            return None;
        }
        Some(Self { far_end, name })
    }

    /// Give the device an address, `cidr` as `ip address add` takes it. IPv6 skips duplicate
    /// address detection, so the address is usable at once.
    pub(crate) fn add_address(&self, cidr: &str) -> bool {
        let mut args = vec!["address", "add", cidr, "dev", &self.name];
        if cidr.contains(':') {
            args.push("nodad");
        }
        std::process::Command::new("ip")
            .args(args)
            .status()
            .is_ok_and(|status| status.success())
    }

    /// The next packet out of the far end, or `None` once `deadline` passes.
    pub(crate) fn next_packet(
        &self,
        deadline: std::time::Instant,
    ) -> std::io::Result<Option<Vec<u8>>> {
        use std::io::Read as _;
        use std::os::fd::AsRawFd;

        let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
            return Ok(None);
        };
        let mut pfd = libc::pollfd {
            fd: self.far_end.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: one `pollfd`, as declared.
        match unsafe { libc::poll(&raw mut pfd, 1, timeout) } {
            0 => return Ok(None),
            n if n < 0 => return Err(std::io::Error::last_os_error()),
            _ => {}
        }
        // One packet per read (`IFF_NO_PI`: no header).
        let mut buf = [0u8; crate::net::MAX_FRAME_LEN];
        let n = (&self.far_end).read(&mut buf)?;
        Ok(Some(buf[..n].to_vec()))
    }

    /// Whether a packet equal to `want` comes out of the far end within two seconds.
    pub(crate) fn read_until(&self, want: &[u8]) -> std::io::Result<bool> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while let Some(packet) = self.next_packet(deadline)? {
            if packet == want {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::{Read, open_or_skip};
    use crate::net::LinkType;

    // Live capture against a real interface (`NETFLECTOR_TEST_IFACE`). Backend-neutral
    // because a real interface is Ethernet-framed on both backends: BPF reports
    // DLT_EN10MB, AF_PACKET delivers the Ethernet header.
    #[test]
    fn live_capture_decodes_real_frames() -> std::io::Result<()> {
        let Some(iface) = std::env::var_os("NETFLECTOR_TEST_IFACE") else {
            eprintln!("skip live_capture: set NETFLECTOR_TEST_IFACE to an Ethernet interface");
            return Ok(());
        };
        let iface = iface.to_string_lossy();
        let Some(mut capture) = open_or_skip(&iface, "live_capture")? else {
            return Ok(());
        };
        assert_eq!(capture.link_type(), LinkType::Ethernet);

        // Every frame the kernel filter passed must be an IPv4/IPv6 Ethernet frame, so a
        // mis-sliced header would corrupt these.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut validated = 0u32;
        while validated < 8 && std::time::Instant::now() < deadline {
            match capture.next_frame()? {
                Some(Read::Oversized) => {}
                Some(Read::Frame(frame)) => {
                    assert!(frame.len() >= 14, "frame shorter than an Ethernet header");
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    assert!(
                        ethertype == 0x0800 || ethertype == 0x86dd,
                        "filter passed a non-IP ethertype {ethertype:#06x}",
                    );
                    validated += 1;
                }
                None => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        eprintln!("live_capture: validated {validated} frame(s) on {iface}");
        Ok(())
    }
}
