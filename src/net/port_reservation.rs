//! An ephemeral-UDP-port reservation: a held, never-read socket that keeps the kernel's UDP demux
//! satisfied. The SSDP search reflector re-emits an M-SEARCH from this port so devices unicast their
//! `200 OK` back to it. The port must stay claimed for the session's lifetime, else the kernel finds
//! no socket for the reply and answers with an ICMP port-unreachable. The raw capture reads the actual
//! datagram, not this socket; on Linux a drop-all BPF filter makes it enqueue nothing. Dropping it
//! frees the port.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};

use crate::sys::{bind, local_addr, open_socket};

/// A reservation over one OS-assigned ephemeral UDP port on an interface's source address. Owns the
/// bound socket; `Drop` frees the port.
pub(crate) struct PortReservation {
    /// Held to keep the port claimed; never read.
    _fd: OwnedFd,
    source: SocketAddr,
}

impl PortReservation {
    /// Reserve an ephemeral port on `addr`, the egress interface's own address that the reflector
    /// sends from and devices reply to. `ifindex` disambiguates an IPv6 link-local `addr` and is
    /// used only for one.
    ///
    /// # Errors
    /// Propagates the socket / filter / bind / `getsockname` syscall failure.
    pub(crate) fn create(addr: IpAddr, ifindex: u32) -> io::Result<Self> {
        let family = match addr {
            IpAddr::V4(_) => libc::AF_INET,
            IpAddr::V6(_) => libc::AF_INET6,
        };
        let fd = open_socket(family, libc::SOCK_DGRAM, 0)?;
        #[cfg(target_os = "linux")]
        attach_drop_all_filter(fd.as_raw_fd())?;
        bind(fd.as_raw_fd(), addr, 0, ifindex)?;
        let port = local_addr(fd.as_raw_fd())?.port();
        Ok(Self {
            _fd: fd,
            source: SocketAddr::new(addr, port),
        })
    }

    /// The OS-assigned ephemeral port the reservation holds.
    pub(crate) fn port(&self) -> u16 {
        self.source.port()
    }

    /// The reserved address and port: what the reflector sends from and devices reply to.
    pub(crate) fn source(&self) -> SocketAddr {
        self.source
    }
}

/// Attach a drop-all classic-BPF filter so the bound socket enqueues nothing: the bind already
/// suppresses the ICMP port-unreachable, and the raw capture reads the real datagram.
#[cfg(target_os = "linux")]
fn attach_drop_all_filter(fd: std::os::fd::RawFd) -> io::Result<()> {
    // A single `BPF_RET | BPF_K` returning 0: accept zero bytes, i.e. drop every packet.
    let drop_all = [libc::sock_filter {
        code: 0x0006,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    let program = libc::sock_fprog {
        len: 1,
        filter: drop_all.as_ptr().cast_mut(),
    };
    crate::sys::setsockopt(fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &program)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn reserves_a_nonzero_port_on_loopback() {
        let r = PortReservation::create(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
            .expect("bind an ephemeral port on loopback");
        assert_ne!(r.port(), 0, "getsockname should report the assigned port");
    }

    // A routable (non-link-local) v6 bind must not carry the ifindex as a zone id. Only FreeBSD
    // rejects the pairing (Linux never reads it, macOS zeroes it), so this has teeth on the
    // FreeBSD lane and pins the contract elsewhere.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn routable_v6_reservation_ignores_the_ifindex() {
        let r = PortReservation::create(IpAddr::V6(Ipv6Addr::LOCALHOST), u32::MAX)
            .expect("bind an ephemeral port on v6 loopback without a zone id");
        assert_ne!(r.port(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn two_reservations_get_distinct_ports() {
        let a = PortReservation::create(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let b = PortReservation::create(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        assert_ne!(a.port(), b.port());
    }
}
