//! Scaffolding shared by the unit tests: privileged-resource probes that self-skip, and stand-in
//! handlers.

use std::fmt;
use std::io;
use std::sync::LazyLock;

use crate::capture::Capture;
use crate::dispatch::{CaptureKey, PacketDispatcher};
use crate::interface::{Interface, LOOPBACK_IFACE};
use crate::reactor::{Handler, Reactor, ReadyEvent};

/// Something a test needs from the host and not every host offers. A test that finds one missing
/// skips with a note, unless `NETFLECTOR_TEST_REQUIRE` (a comma-separated list of the names
/// below) lists it: then the test fails, so a CI lane set up to provide the facility cannot go
/// green without it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Capability {
    /// A raw capture on the loopback interface: `CAP_NET_RAW`, or access to `/dev/bpf`.
    Capture,
    /// `MCAST_JOIN_GROUP` on the loopback interface; QEMU user mode refuses it.
    Membership,
    /// A connected interface pair (veth, feth, epair): root and the platform's tooling.
    Pair,
    /// A tun device: root and `/dev/net/tun`.
    #[cfg(target_os = "linux")]
    Tun,
    /// `::1` usable.
    Ipv6,
    /// The interface monitor's socket; some sandboxes deny it.
    Monitor,
    /// A `WireGuard` interface: root and wg(8).
    #[cfg(any(target_os = "freebsd", target_os = "linux"))]
    WireGuard,
}

impl Capability {
    fn name(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Membership => "membership",
            Self::Pair => "pair",
            #[cfg(target_os = "linux")]
            Self::Tun => "tun",
            Self::Ipv6 => "ipv6",
            Self::Monitor => "monitor",
            #[cfg(any(target_os = "freebsd", target_os = "linux"))]
            Self::WireGuard => "wireguard",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "capture" => Self::Capture,
            "membership" => Self::Membership,
            "pair" => Self::Pair,
            #[cfg(target_os = "linux")]
            "tun" => Self::Tun,
            "ipv6" => Self::Ipv6,
            "monitor" => Self::Monitor,
            #[cfg(any(target_os = "freebsd", target_os = "linux"))]
            "wireguard" => Self::WireGuard,
            _ => return None,
        })
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The capabilities `NETFLECTOR_TEST_REQUIRE` lists. A name this platform does not know is a
/// misconfigured lane and panics.
fn required_capabilities() -> &'static [Capability] {
    static REQUIRED: LazyLock<Vec<Capability>> = LazyLock::new(|| {
        let list = match std::env::var("NETFLECTOR_TEST_REQUIRE") {
            Ok(list) => list,
            Err(std::env::VarError::NotPresent) => return Vec::new(),
            Err(e) => panic!("NETFLECTOR_TEST_REQUIRE: {e}"),
        };
        list.split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| {
                Capability::from_name(name).unwrap_or_else(|| {
                    panic!("NETFLECTOR_TEST_REQUIRE: unknown capability {name:?}")
                })
            })
            .collect()
    });
    &REQUIRED
}

/// Note that the test skips for want of `cap`, or fail it when the lane requires `cap`.
pub(crate) fn skip(cap: Capability, reason: impl fmt::Display) {
    assert!(
        !required_capabilities().contains(&cap),
        "{cap} is required by NETFLECTOR_TEST_REQUIRE: {reason}"
    );
    eprintln!("skip {cap}: {reason}");
}

/// Open a capture on `if_name`, or `Ok(None)` (skip) when the host can't: no BPF access /
/// `CAP_NET_RAW`, or the interface is absent. Other errors propagate for the caller to `?`.
pub(crate) fn open_or_skip(if_name: &str) -> io::Result<Option<Capture>> {
    skip_unless_captured(
        if_name,
        Interface::open(if_name).and_then(|interface| Capture::open(&interface)),
    )
}

/// [`open_or_skip`] into `dispatcher`, which keeps the capture.
pub(crate) fn open_capture_or_skip(
    dispatcher: &mut PacketDispatcher,
    if_name: &str,
) -> io::Result<Option<CaptureKey>> {
    skip_unless_captured(if_name, dispatcher.open_capture(if_name))
}

/// A loopback capture in `dispatcher`, or `None` (skip) without `CAP_NET_RAW`.
pub(crate) fn open_loopback_or_skip(dispatcher: &mut PacketDispatcher) -> Option<CaptureKey> {
    open_capture_or_skip(dispatcher, LOOPBACK_IFACE)
        .expect("unexpected loopback capture open failure")
}

fn skip_unless_captured<T>(if_name: &str, opened: io::Result<T>) -> io::Result<Option<T>> {
    match opened {
        Ok(opened) => Ok(Some(opened)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
            ) =>
        {
            skip(
                Capability::Capture,
                format_args!("cannot capture on {if_name} ({e})"),
            );
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// The tests that open a capture on the loopback interface hold this for their duration: every
/// descriptor attached there sees every frame, and the kernel's small double buffer drops what
/// a concurrent test's traffic leaves no room for.
pub(crate) fn loopback_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A handler that does nothing: a placeholder the reactor hands registrations and a key out for.
pub(crate) struct NoopHandler;

impl Handler for NoopHandler {
    fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
}

/// A reply transform that replaces the payload wholesale, standing in for a DIAL rewrite that
/// spliced in the proxy's own listener.
pub(crate) struct ReplaceRewrite;

impl crate::reflector::ReplyRewrite for ReplaceRewrite {
    fn rewrite<'a>(
        &'a mut self,
        _: &[u8],
        _: crate::dispatch::CaptureKey,
        _: &mut crate::dispatch::PacketDispatcher,
        _: &mut Reactor,
    ) -> Option<&'a [u8]> {
        Some(b"REWRITTEN")
    }
}

/// A tun device attached to this process: its kernel side is a raw IP link, `far_end` the other
/// side, where a packet written arrives on the link and one sent on the link comes out. Gone
/// when the file closes. For the raw IP link tests.
#[cfg(target_os = "linux")]
pub(crate) struct Tun {
    pub(crate) far_end: std::fs::File,
    pub(crate) name: String,
}

#[cfg(target_os = "linux")]
impl Tun {
    /// `None`, with a note, where the test can't run: no root, no `/dev/net/tun`, or a kernel
    /// (user-mode QEMU) that refuses the attach.
    pub(crate) fn create() -> Option<Self> {
        use std::os::fd::AsRawFd;

        // A `%d` template asks for a kernel-assigned name, written back by the ioctl.
        const TEMPLATE: &[u8] = b"nftun%d";
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            skip(Capability::Tun, "creating a tun device requires root");
            return None;
        }
        let far_end = match std::fs::File::options()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
        {
            Ok(file) => file,
            Err(e) => {
                skip(Capability::Tun, format_args!("/dev/net/tun: {e}"));
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
            skip(
                Capability::Tun,
                format_args!("TUNSETIFF: {}", std::io::Error::last_os_error()),
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
            skip(
                Capability::Tun,
                format_args!("cannot bring {name} up (no ip(8)?)"),
            );
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
    use super::*;

    // Forces the parse on every lane, so a misspelled name fails even where nothing skips.
    #[test]
    fn require_list_parses() {
        required_capabilities();
    }
}
