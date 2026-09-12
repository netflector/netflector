//! Small syscall helpers shared across subsystems. macOS lacks `pipe2` and the `SOCK_*` type
//! flags, so it applies close-on-exec and non-blocking by `fcntl`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::ptr;

use libc::{c_int, c_void, socklen_t};

/// Take ownership of a fd-returning syscall's result.
///
/// # Errors
/// The last OS error when `raw` is negative.
pub(crate) fn owned_fd_from(raw: RawFd) -> io::Result<OwnedFd> {
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a non-negative return from a fd-returning syscall is a fresh fd we exclusively own.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// The result of a syscall that returns 0 on success and -1 on failure.
///
/// # Errors
/// The last OS error when `rc` is negative.
pub(crate) fn check(rc: c_int) -> io::Result<()> {
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The status of a non-blocking read/write syscall.
pub(crate) enum IoStatus {
    /// Bytes transferred, possibly 0; the caller decides what 0 means.
    Ready(usize),
    /// `EAGAIN`/`EWOULDBLOCK`.
    WouldBlock,
}

impl IoStatus {
    /// `EINTR` is not special-cased: the shutdown signals install with `SA_RESTART`, so
    /// restartable read/write calls auto-restart; only the reactor wait can see it, and it
    /// retries itself.
    ///
    /// # Errors
    /// The last OS error for any errno other than `EAGAIN`/`EWOULDBLOCK`.
    pub(crate) fn from_syscall(n: isize) -> io::Result<IoStatus> {
        if n >= 0 {
            return Ok(IoStatus::Ready(
                usize::try_from(n).expect("a non-negative transfer count fits usize"),
            ));
        }
        let err = io::Error::last_os_error();
        if would_block(&err) {
            return Ok(IoStatus::WouldBlock);
        }
        Err(err)
    }
}

/// `EAGAIN` and `EWOULDBLOCK` are equal on our targets, so an or-pattern's second arm would be
/// unreachable; hence the guard.
pub(crate) fn would_block(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK)
}

pub(crate) fn socklen_of<T>() -> socklen_t {
    socklen_t::try_from(size_of::<T>()).expect("option/address size fits socklen_t")
}

/// Read and clear the socket's pending error: a non-blocking connect's outcome, or an
/// asynchronous error the kernel parked (`ENETDOWN` on a packet socket whose interface died).
pub(crate) fn so_error(fd: RawFd) -> io::Result<c_int> {
    getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_ERROR)
}

/// # Errors
/// The OS error if the option can't be set.
pub(crate) fn setsockopt<T>(fd: RawFd, level: c_int, name: c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` is a live `T` passed with its own size; the kernel only reads it.
    check(unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const *value).cast::<c_void>(),
            socklen_of::<T>(),
        )
    })
}

/// # Errors
/// The OS error if the option can't be read.
pub(crate) fn getsockopt_int(fd: RawFd, level: c_int, name: c_int) -> io::Result<c_int> {
    let mut value: c_int = 0;
    let mut len = socklen_of::<c_int>();
    // SAFETY: `value`/`len` are a valid (c_int, length) out-pair for `fd`.
    check(unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&raw mut value).cast::<c_void>(),
            &raw mut len,
        )
    })?;
    Ok(value)
}

/// `SO_RCVTIMEO`: an answer that never arrives surfaces as would-block instead of parking the
/// reactor. Only the synchronous request/reply sockets need it.
///
/// # Errors
/// The OS error if the option can't be set.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) fn set_recv_timeout(fd: RawFd, timeout: std::time::Duration) -> io::Result<()> {
    // `suseconds_t` is 32-bit on some targets and 64-bit on musl: the conversion must stay
    // fallible for the former, and clippy objects where it can't fail.
    #[allow(clippy::unnecessary_fallible_conversions)]
    let tv_usec = timeout
        .subsec_micros()
        .try_into()
        .expect("a sub-second microsecond count fits tv_usec");
    let tv = libc::timeval {
        tv_sec: timeout
            .as_secs()
            .try_into()
            .expect("the timeout's seconds fit tv_sec"),
        tv_usec,
    };
    setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv)
}

/// Raise the soft open-file limit to the hard one (needs no privilege). A DIAL proxy costs two
/// listener fds plus two per connection, and each search session holds a port reservation.
pub(crate) fn raise_file_limit() {
    // SAFETY: an all-zero `rlimit` is a valid value for `getrlimit` to overwrite.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: `&limit` is a valid out-param for the given resource.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } != 0 {
        log::warn!(
            "could not read the open-file limit: {}",
            io::Error::last_os_error()
        );
        return;
    }
    if limit.rlim_cur >= limit.rlim_max {
        log::debug!("open-file limit already {}", show_limit(limit.rlim_cur));
        return;
    }
    let raised = libc::rlimit {
        rlim_cur: limit.rlim_max,
        rlim_max: limit.rlim_max,
    };
    // SAFETY: `&raised` is a valid `rlimit` for the given resource.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const raised) } != 0 {
        log::warn!(
            "could not raise the open-file limit from {} to {}: {}",
            limit.rlim_cur,
            show_limit(limit.rlim_max),
            io::Error::last_os_error()
        );
        return;
    }
    log::debug!(
        "raised the open-file limit from {} to {}",
        limit.rlim_cur,
        show_limit(limit.rlim_max)
    );
}

/// macOS reports an infinite hard limit; the number for that is noise.
fn show_limit(limit: libc::rlim_t) -> String {
    if limit == libc::RLIM_INFINITY {
        "unlimited".to_owned()
    } else {
        limit.to_string()
    }
}

/// `SO_RERROR` (FreeBSD 13.0+): a receive-queue overflow fails the next `recv` with `ENOBUFS`
/// instead of being dropped silently. macOS has no equivalent; Linux netlink reports overflow
/// already.
///
/// # Errors
/// The OS error if the option can't be set.
#[cfg(target_os = "freebsd")]
pub(crate) fn set_recv_error_reporting(fd: RawFd) -> io::Result<()> {
    setsockopt(fd, libc::SOL_SOCKET, libc::SO_RERROR, &1 as &c_int)
}

/// Best-effort. Leaves an already-larger queue alone: `SO_RCVBUF` sets an absolute size, so an
/// operator's raised default would otherwise be cut back. Linux netlink defaults to the system
/// max and needs none of this.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn increase_recv_buffer(fd: RawFd, bytes: c_int) {
    match getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF) {
        Err(e) => log::warn!(
            "could not read the socket receive buffer size, requesting {bytes} bytes anyway: {e}"
        ),
        Ok(current) if current >= bytes => {
            log::trace!(
                "socket receive buffer already {current} bytes, at or above the {bytes} wanted; leaving it"
            );
            return;
        }
        Ok(_) => {}
    }
    set_recv_buffer(fd, bytes);
}

/// Kernel-clamped; a failure is logged, not returned, since the default buffer still works.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn set_recv_buffer(fd: RawFd, bytes: c_int) {
    if let Err(e) = setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &bytes) {
        log::warn!("could not set the socket receive buffer to {bytes} bytes: {e}");
    }
}

/// A close-on-exec, non-blocking socket.
///
/// # Errors
/// The OS error if the socket can't be opened (or, on macOS, the flags can't be set).
pub(crate) fn open_socket(family: c_int, base_type: c_int, protocol: c_int) -> io::Result<OwnedFd> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let fd = socket(
        family,
        base_type | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        protocol,
    )?;
    #[cfg(target_os = "macos")]
    let fd = socket(family, base_type, protocol)?;
    #[cfg(target_os = "macos")]
    set_cloexec_nonblock(fd.as_raw_fd())?;
    Ok(fd)
}

/// A close-on-exec, blocking socket: for a synchronous request/reply exchange the reactor never
/// polls.
///
/// # Errors
/// The OS error if the socket can't be opened.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) fn blocking_socket(
    family: c_int,
    base_type: c_int,
    protocol: c_int,
) -> io::Result<OwnedFd> {
    socket(family, base_type | libc::SOCK_CLOEXEC, protocol)
}

fn socket(family: c_int, ty: c_int, protocol: c_int) -> io::Result<OwnedFd> {
    // SAFETY: `socket` returns a fresh fd or -1.
    owned_fd_from(unsafe { libc::socket(family, ty, protocol) })
}

/// `bind` `fd` to `addr`:`port`, with `scope_id` as [`sockaddr_for`] applies it.
///
/// # Errors
/// The OS error if the bind fails.
pub(crate) fn bind(fd: RawFd, addr: IpAddr, port: u16, scope_id: u32) -> io::Result<()> {
    let (storage, len) = sockaddr_for(addr, port, scope_id);
    // SAFETY: `storage` holds a `sockaddr_in`/`sockaddr_in6` of `len` bytes.
    check(unsafe { libc::bind(fd, (&raw const storage).cast::<libc::sockaddr>(), len) })
}

/// The address `fd` is bound to.
///
/// # Errors
/// The OS error if the name can't be read, or a socket of neither IP family.
pub(crate) fn local_addr(fd: RawFd) -> io::Result<SocketAddr> {
    // SAFETY: an all-zero `sockaddr_storage` is a valid out-buffer; `getsockname` fills it.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = socklen_of::<libc::sockaddr_storage>();
    // SAFETY: `storage`/`len` are a valid (sockaddr, length) out-pair for `fd`.
    check(unsafe {
        libc::getsockname(
            fd,
            (&raw mut storage).cast::<libc::sockaddr>(),
            &raw mut len,
        )
    })?;
    match c_int::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says the storage holds a `sockaddr_in`, plain data it is large
            // enough and aligned for.
            let sin = unsafe { ptr::read((&raw const storage).cast::<libc::sockaddr_in>()) };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: as above, for a `sockaddr_in6`.
            let sin6 = unsafe { ptr::read((&raw const storage).cast::<libc::sockaddr_in6>()) };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        other => Err(io::Error::other(format!(
            "socket family {other} is neither IPv4 nor IPv6"
        ))),
    }
}

/// Marshal `addr`:`port` into a `sockaddr_storage`, returning it with the family-specific
/// length. The BSD kernels require `sin*_len`. `scope_id` is written only where the kernel
/// consults it ([`needs_scope_id`]) and zeroed otherwise, so callers pass their interface index
/// unconditionally: FreeBSD rejects a bind carrying a nonzero `sin6_scope_id` on any other
/// address (`EADDRNOTAVAIL`).
pub(crate) fn sockaddr_for(
    addr: IpAddr,
    port: u16,
    scope_id: u32,
) -> (libc::sockaddr_storage, socklen_t) {
    // SAFETY: an all-zero `sockaddr_storage` is a valid (AF_UNSPEC) value; the family and address
    // are overwritten below through a correctly-typed pointer into storage large enough for them.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        IpAddr::V4(v4) => {
            let sin = (&raw mut storage).cast::<libc::sockaddr_in>();
            // SAFETY: `storage` outlives `sin` and is larger than `sockaddr_in`.
            unsafe {
                (*sin).sin_family =
                    libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET fits sa_family_t");
                (*sin).sin_port = port.to_be();
                (*sin).sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.octets()),
                };
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                {
                    (*sin).sin_len =
                        u8::try_from(size_of::<libc::sockaddr_in>()).expect("sockaddr_in fits u8");
                }
            }
            socklen_of::<libc::sockaddr_in>()
        }
        IpAddr::V6(v6) => {
            let sin6 = (&raw mut storage).cast::<libc::sockaddr_in6>();
            // SAFETY: `storage` outlives `sin6` and is larger than `sockaddr_in6`.
            unsafe {
                (*sin6).sin6_family =
                    libc::sa_family_t::try_from(libc::AF_INET6).expect("AF_INET6 fits sa_family_t");
                (*sin6).sin6_port = port.to_be();
                (*sin6).sin6_addr = libc::in6_addr {
                    s6_addr: v6.octets(),
                };
                (*sin6).sin6_scope_id = if needs_scope_id(v6) { scope_id } else { 0 };
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                {
                    (*sin6).sin6_len = u8::try_from(size_of::<libc::sockaddr_in6>())
                        .expect("sockaddr_in6 fits u8");
                }
            }
            socklen_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len)
}

/// Whether the kernel consults `sin6_scope_id`: link-local unicast, or interface- (`ff01::`) or
/// link-scoped (`ff02::`) multicast. For everything else, site-scoped multicast included, Linux
/// ignores the field, macOS zeroes it, and FreeBSD rejects binds that carry it.
fn needs_scope_id(v6: Ipv6Addr) -> bool {
    const INTERFACE_LOCAL: u16 = 1;
    const LINK_LOCAL: u16 = 2;
    v6.is_unicast_link_local()
        || (v6.is_multicast() && matches!(v6.segments()[0] & 0xf, INTERFACE_LOCAL | LINK_LOCAL))
}

/// Read-modify-write so any other flags survive.
///
/// # Errors
/// The first failing `fcntl`'s error.
#[cfg(target_os = "macos")]
pub(crate) fn set_cloexec_nonblock(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid open fd; F_GETFD returns the descriptor flags.
    let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is valid; F_SETFD writes the descriptor flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    set_nonblock(fd)
}

#[cfg(target_os = "macos")]
fn set_nonblock(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is valid; F_GETFL returns the status flags.
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is valid; F_SETFL writes the status flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, status | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The process environment as UTF-8 key/value pairs; non-UTF-8 entries are skipped.
///
/// Walks the crt1-provided `environ` itself instead of calling `std::env::vars`: std resolves
/// `environ` via `dlsym(RTLD_DEFAULT, ..)`, which is null in a statically linked binary, and
/// the shipped static binary segfaulted on startup. Rust 1.99 ships the upstream fix; drop
/// this at that bump.
#[cfg(target_os = "freebsd")]
pub(crate) fn process_env() -> Vec<(String, String)> {
    unsafe extern "C" {
        static mut environ: *mut *const libc::c_char;
    }
    let mut entries = Vec::new();
    // SAFETY: crt1 points `environ` at the null-terminated environment before
    // `main` and libc's setenv keeps it valid; the process is single-threaded
    // (project invariant), so the table cannot change mid-walk; each entry is
    // a valid C string.
    unsafe {
        let mut entry = environ;
        while !entry.is_null() && !(*entry).is_null() {
            let bytes = std::ffi::CStr::from_ptr(*entry).to_bytes();
            if let Some((key, value)) = str::from_utf8(bytes).ok().and_then(|s| s.split_once('=')) {
                entries.push((key.to_owned(), value.to_owned()));
            }
            entry = entry.add(1);
        }
    }
    entries
}

/// The process environment as UTF-8 key/value pairs; non-UTF-8 entries are skipped.
#[cfg(not(target_os = "freebsd"))]
pub(crate) fn process_env() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn sockaddr_for_v4_marshals_a_sockaddr_in() {
        let (sa, len) = sockaddr_for(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 0, 0);
        assert_eq!(len, socklen_of::<libc::sockaddr_in>());
        // SAFETY: `sockaddr_for` wrote a `sockaddr_in` into the storage for a V4 address.
        let sin = unsafe { &*(&raw const sa).cast::<libc::sockaddr_in>() };
        assert_eq!(
            sin.sin_family,
            libc::sa_family_t::try_from(libc::AF_INET).unwrap()
        );
        assert_eq!(sin.sin_addr.s_addr, u32::from_ne_bytes([224, 0, 0, 251]));
        assert_eq!(sin.sin_port, 0);
    }

    #[test]
    fn sockaddr_for_v6_carries_the_scope_id() {
        let v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let (sa, len) = sockaddr_for(IpAddr::V6(v6), 0, 7);
        assert_eq!(len, socklen_of::<libc::sockaddr_in6>());
        // SAFETY: `sockaddr_for` wrote a `sockaddr_in6` into the storage for a V6 address.
        let sin6 = unsafe { &*(&raw const sa).cast::<libc::sockaddr_in6>() };
        assert_eq!(
            sin6.sin6_family,
            libc::sa_family_t::try_from(libc::AF_INET6).unwrap()
        );
        assert_eq!(sin6.sin6_addr.s6_addr, v6.octets());
        assert_eq!(sin6.sin6_scope_id, 7);
    }

    fn scope_written_for(addr: &str) -> u32 {
        let v6: Ipv6Addr = addr.parse().unwrap();
        let (sa, _) = sockaddr_for(IpAddr::V6(v6), 0, 7);
        // SAFETY: `sockaddr_for` wrote a `sockaddr_in6` into the storage for a V6 address.
        unsafe { (*(&raw const sa).cast::<libc::sockaddr_in6>()).sin6_scope_id }
    }

    #[test]
    fn sockaddr_for_keeps_the_scope_id_for_link_scoped_multicast() {
        assert_eq!(scope_written_for("ff02::fb"), 7);
        assert_eq!(scope_written_for("ff01::1"), 7);
    }

    #[test]
    fn sockaddr_for_zeroes_the_scope_id_where_the_kernel_ignores_it() {
        assert_eq!(scope_written_for("2001:db8::1"), 0);
        assert_eq!(scope_written_for("fd00::1"), 0);
        assert_eq!(scope_written_for("ff05::c"), 0);
        assert_eq!(scope_written_for("::1"), 0);
    }

    /// The process's current open-file limits.
    fn file_limit() -> (libc::rlim_t, libc::rlim_t) {
        // SAFETY: an all-zero `rlimit` is a valid value for `getrlimit` to overwrite.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `&limit` is a valid out-param for the given resource.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) };
        assert_eq!(rc, 0, "getrlimit failed");
        (limit.rlim_cur, limit.rlim_max)
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real getrlimit")]
    fn raising_the_file_limit_reaches_the_hard_limit() {
        let (before, hard) = file_limit();
        raise_file_limit();
        let (after, _) = file_limit();
        assert!(
            after >= before,
            "the soft limit was lowered: {after} < {before}"
        );
        assert_eq!(after, hard, "the soft limit ends at the hard limit");
    }

    #[test]
    fn would_block_matches_only_eagain_and_ewouldblock() {
        assert!(would_block(&io::Error::from_raw_os_error(libc::EAGAIN)));
        assert!(would_block(&io::Error::from_raw_os_error(
            libc::EWOULDBLOCK
        )));
        assert!(!would_block(&io::Error::from_raw_os_error(libc::EPERM)));
    }

    #[test]
    fn from_syscall_maps_a_nonnegative_count_to_ready() {
        assert!(matches!(IoStatus::from_syscall(0), Ok(IoStatus::Ready(0))));
        assert!(matches!(IoStatus::from_syscall(7), Ok(IoStatus::Ready(7))));
    }

    #[test]
    fn owned_fd_from_rejects_a_negative_return() {
        assert!(owned_fd_from(-1).is_err());
    }

    #[test]
    fn process_env_sees_a_set_variable() {
        // SAFETY: nothing else in the test binary reads or writes the process
        // environment concurrently (config tests take env as a parameter).
        unsafe { std::env::set_var("NETFLECTOR_SYS_ENV_PROBE", "probe-value") };
        let env = process_env();
        assert!(
            env.iter()
                .any(|(k, v)| k == "NETFLECTOR_SYS_ENV_PROBE" && v == "probe-value")
        );
    }
}
