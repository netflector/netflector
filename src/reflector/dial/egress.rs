//! Confining a device connection to the target interface, so a route lookup can't leak it onto the
//! wrong segment. Linux pins the socket with `SO_BINDTODEVICE` and macOS with `IP_BOUND_IF` (the
//! name resolved to its current index, so the pin follows the name across a recreation). FreeBSD has
//! no such primitive and checks the route instead: weaker, since it can't hold an established
//! connection in place, and under multipath the kernel reports the first nexthop while the connect
//! hashes independently.

use std::io;
use std::net::SocketAddrV4;
use std::os::fd::RawFd;

/// Confine the unconnected socket `fd` to the interface `iface` names before it connects to `dst`;
/// `None` skips the confinement.
///
/// # Errors
/// An unknown interface, or the pin's `setsockopt` failure.
#[cfg(not(target_os = "freebsd"))]
pub(super) fn confine(fd: RawFd, _dst: SocketAddrV4, iface: Option<&str>) -> io::Result<()> {
    let Some(name) = iface else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        if name.len() >= libc::IF_NAMESIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        // SAFETY: `name` points at `name.len()` valid bytes; the kernel NUL-terminates its copy.
        crate::sys::check(unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr().cast::<libc::c_void>(),
                libc::socklen_t::try_from(name.len())
                    .expect("interface name length fits socklen_t"),
            )
        })?;
    }
    #[cfg(target_os = "macos")]
    {
        let index = crate::interface::if_index(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface {name} not found"),
            )
        })?;
        let index =
            libc::c_int::try_from(index).map_err(|_| io::Error::other("ifindex too large"))?;
        crate::sys::setsockopt(fd, libc::IPPROTO_IP, libc::IP_BOUND_IF, &index)?;
    }
    log::trace!("connect egress pinned to {name}");
    Ok(())
}

/// Refuse a connect to `dst` whose route would leave by an interface other than the one `iface`
/// names; `None` skips the check.
///
/// # Errors
/// An unknown interface, a routing-socket failure, or a destination that routes elsewhere.
#[cfg(target_os = "freebsd")]
pub(super) fn confine(_fd: RawFd, dst: SocketAddrV4, iface: Option<&str>) -> io::Result<()> {
    let Some(name) = iface else {
        return Ok(());
    };
    let want = crate::interface::if_index(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {name} not found"),
        )
    })?;
    let got = crate::net::route_query::egress_ifindex(*dst.ip())?;
    if got == want {
        log::trace!("{} is reachable via {name}", dst.ip());
        return Ok(());
    }
    let via = crate::interface::if_name(got).unwrap_or_else(|| format!("interface {got}"));
    let ip = dst.ip();
    Err(io::Error::other(format!(
        "{ip} routes via {via}, not {name}"
    )))
}
