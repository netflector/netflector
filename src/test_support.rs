//! Scaffolding shared by the unit tests: privileged-resource probes that self-skip, and stand-in
//! handlers.

use std::io;

use crate::capture::Capture;
use crate::interface::LOOPBACK_IFACE;
use crate::reactor::{Handler, Reactor, ReadyEvent};

/// Open a capture on `if_name`, or `Ok(None)` (with a note) when the host can't: no BPF access /
/// `CAP_NET_RAW`, or the interface is absent. Other errors propagate for the caller to `?`.
pub(crate) fn open_or_skip(if_name: &str, what: &str) -> io::Result<Option<Capture>> {
    match Capture::open(if_name) {
        Ok(capture) => Ok(Some(capture)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
            ) =>
        {
            eprintln!("skip {what}: cannot capture on {if_name} ({e})");
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// A loopback capture, or `None` (skip) without `CAP_NET_RAW`.
pub(crate) fn open_loopback_or_skip() -> Option<Capture> {
    open_or_skip(LOOPBACK_IFACE, "loopback capture")
        .expect("unexpected loopback capture open failure")
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
