//! A non-blocking, close-on-exec IPv4 TCP socket for the DIAL application proxy; the reactor
//! watches its fd.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::{c_int, c_void};

use crate::sys::{
    IoStatus, check, local_addr, open_socket, setsockopt, so_error, sockaddr_for, would_block,
};

/// A DIAL listener fields a few short-lived client fetches; 16 is ample.
const LISTEN_BACKLOG: c_int = 16;

/// A listener, an accepted connection, or an outbound connection still completing its
/// non-blocking `connect`.
pub(crate) struct TcpSocket {
    fd: OwnedFd,
    local_addr: SocketAddrV4,
    connecting: bool,
}

impl TcpSocket {
    /// Listen on an ephemeral port at `addr` rather than `0.0.0.0`, so the listener is not offered
    /// on every interface. That doesn't stop another segment routing to the address; only a
    /// firewall does.
    ///
    /// # Errors
    /// The socket / `bind` / `listen` failure.
    pub(crate) fn listen(addr: Ipv4Addr) -> io::Result<Self> {
        let fd = open_socket(libc::AF_INET, libc::SOCK_STREAM, 0)?;
        crate::sys::bind(fd.as_raw_fd(), IpAddr::V4(addr), 0, 0)?;
        // SAFETY: `fd` is a valid bound socket; `listen` marks it passive.
        check(unsafe { libc::listen(fd.as_raw_fd(), LISTEN_BACKLOG) })?;
        let local_addr = local_addr_v4(fd.as_raw_fd())?;
        Ok(Self {
            fd,
            local_addr,
            connecting: false,
        })
    }

    pub(crate) fn local_addr(&self) -> SocketAddrV4 {
        self.local_addr
    }

    /// `None` when there is nothing to take: nothing pending, or the pending connection died before
    /// we reached it (see `nothing_to_accept`).
    ///
    /// # Errors
    /// An `accept` failure that leaves the connection queued, or the `setsockopt` failure.
    pub(crate) fn accept(&self) -> io::Result<Option<Self>> {
        let Some(fd) = accept_fd(self.fd.as_raw_fd())? else {
            return Ok(None);
        };
        set_nodelay(fd.as_raw_fd())?;
        Ok(Some(Self {
            fd,
            local_addr: self.local_addr,
            connecting: false,
        }))
    }

    /// `confine` runs on the fresh socket before it binds, for the caller to pin its egress: the
    /// `source` bind alone confines nothing, `ip_output` picks the interface from the destination.
    /// The socket is [`is_connecting`](Self::is_connecting) until a writable edge and
    /// [`finish_connect`](Self::finish_connect).
    ///
    /// # Errors
    /// The socket / `setsockopt` / `confine` / `bind` / `connect` failure, `EINPROGRESS` excepted.
    pub(crate) fn connect(
        dst: SocketAddrV4,
        source: Ipv4Addr,
        confine: impl FnOnce(RawFd) -> io::Result<()>,
    ) -> io::Result<Self> {
        let fd = open_socket(libc::AF_INET, libc::SOCK_STREAM, 0)?;
        set_nodelay(fd.as_raw_fd())?;
        confine(fd.as_raw_fd())?;
        crate::sys::bind(fd.as_raw_fd(), IpAddr::V4(source), 0, 0)?;
        let local_addr = local_addr_v4(fd.as_raw_fd())?;
        let connecting = connect_v4(fd.as_raw_fd(), dst)?;
        Ok(Self {
            fd,
            local_addr,
            connecting,
        })
    }

    /// Call after the writable edge.
    ///
    /// # Errors
    /// The connect's own error (e.g. `ECONNREFUSED`), or the `getsockopt` failure.
    pub(crate) fn finish_connect(&mut self) -> io::Result<()> {
        let err = so_error(self.fd.as_raw_fd())?;
        if err != 0 {
            return Err(io::Error::from_raw_os_error(err));
        }
        self.connecting = false;
        Ok(())
    }

    pub(crate) fn is_connecting(&self) -> bool {
        self.connecting
    }

    /// `Ready(0)` is the peer closing its write side. `buf` must be non-empty: a zero-length `recv`
    /// also returns 0 and would alias that EOF.
    ///
    /// # Errors
    /// A read error other than `EAGAIN`/`EWOULDBLOCK`.
    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<IoStatus> {
        debug_assert!(
            !buf.is_empty(),
            "recv into an empty buffer returns 0, aliasing EOF"
        );
        // SAFETY: `buf` is a valid writable region of `buf.len()` bytes.
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                0,
            )
        };
        IoStatus::from_syscall(n)
    }

    /// A write to a reset peer returns `EPIPE` rather than raising `SIGPIPE`: Rust ignores the
    /// signal process-wide.
    ///
    /// # Errors
    /// A write error other than `EAGAIN`/`EWOULDBLOCK`.
    pub(crate) fn send(&self, buf: &[u8]) -> io::Result<IoStatus> {
        // SAFETY: `buf` is a valid readable region of `buf.len()` bytes.
        let n = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                buf.as_ptr().cast::<c_void>(),
                buf.len(),
                0,
            )
        };
        IoStatus::from_syscall(n)
    }

    /// # Errors
    /// A write error other than `EAGAIN`/`EWOULDBLOCK`.
    pub(crate) fn send_vectored(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<IoStatus> {
        let iovcnt = c_int::try_from(bufs.len()).unwrap_or(c_int::MAX);
        // SAFETY: `io::IoSlice` is ABI-compatible with `iovec`; `bufs.as_ptr()`/`iovcnt` describe a
        // valid array of that many slices for `writev`.
        let n = unsafe {
            libc::writev(
                self.fd.as_raw_fd(),
                bufs.as_ptr().cast::<libc::iovec>(),
                iovcnt,
            )
        };
        IoStatus::from_syscall(n)
    }

    /// Best-effort: FIN both directions now rather than waiting for `Drop`.
    pub(crate) fn shutdown(&self) {
        // SAFETY: `fd` is a valid socket; shutdown of an already-closed peer is a harmless error.
        unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_RDWR) };
    }

    /// Best-effort half-close: FIN our write half, the read half stays open.
    pub(crate) fn shutdown_write(&self) {
        // SAFETY: `fd` is a valid socket; shutting an already-closed write half is a harmless error.
        unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_WR) };
    }
}

impl AsRawFd for TcpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn local_addr_v4(fd: RawFd) -> io::Result<SocketAddrV4> {
    match local_addr(fd)? {
        std::net::SocketAddr::V4(addr) => Ok(addr),
        std::net::SocketAddr::V6(_) => Err(io::Error::other("the socket is not IPv4")),
    }
}

fn accept_fd(fd: RawFd) -> io::Result<Option<OwnedFd>> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    // SAFETY: null addr/len out-pointers are valid; we don't want the peer address.
    let raw = unsafe {
        libc::accept4(
            fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: as above; the flags are applied below by `fcntl`.
    let raw = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if raw < 0 {
        let err = io::Error::last_os_error();
        if nothing_to_accept(&err) {
            return Ok(None);
        }
        return Err(err);
    }
    // SAFETY: a non-negative `accept` return is a fresh fd we exclusively own.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    #[cfg(target_os = "macos")]
    crate::sys::set_cloexec_nonblock(fd.as_raw_fd())?;
    Ok(Some(fd))
}

/// Whether a failed `accept` left nothing to take: nothing was pending (`EAGAIN`), or the pending
/// connection is already gone (the peer aborted after the handshake, or an error queued against
/// that connection surfaced here). The kernel has dropped it, so the readiness clears on its own;
/// `accept(2)` says to treat these like `EAGAIN`.
///
/// Not a catch-all: `EMFILE`/`ENFILE` fail before a descriptor exists and leave the connection
/// queued, so a level-triggered listener re-fires on it forever. Those must reach the caller so it
/// can shed the listener.
fn nothing_to_accept(err: &io::Error) -> bool {
    would_block(err)
        || matches!(
            err.raw_os_error(),
            Some(
                libc::ECONNABORTED
                    | libc::EPROTO
                    | libc::ENETDOWN
                    | libc::ENETUNREACH
                    | libc::EHOSTDOWN
                    | libc::EHOSTUNREACH
                    | libc::ENOPROTOOPT
                    | libc::EOPNOTSUPP
            )
        )
}

/// `true` if the connect is still in progress (`EINPROGRESS`), `false` if it completed at once
/// (loopback).
fn connect_v4(fd: RawFd, dst: SocketAddrV4) -> io::Result<bool> {
    let (storage, len) = sockaddr_for(IpAddr::V4(*dst.ip()), dst.port(), 0);
    // SAFETY: `storage` is a valid `sockaddr_in` of length `len` for `fd`.
    let rc = unsafe { libc::connect(fd, (&raw const storage).cast::<libc::sockaddr>(), len) };
    if rc == 0 {
        return Ok(false);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EINPROGRESS) {
        return Ok(true);
    }
    Err(err)
}

/// Disable Nagle. The proxy forwards at recv granularity and never re-coalesces, so a message
/// spanning two writes would have its sub-MSS tail held behind the first write's unacked bytes
/// until the peer's delayed ACK (40-100ms); the peer is mid-body with nothing to send, so it can't
/// ACK early.
fn set_nodelay(fd: RawFd) -> io::Result<()> {
    setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, &1 as &c_int)
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;

    /// Read back the `TCP_NODELAY` flag via `getsockopt`.
    fn nodelay(socket: &TcpSocket) -> bool {
        crate::sys::getsockopt_int(socket.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_NODELAY)
            .expect("getsockopt(TCP_NODELAY) failed")
            != 0
    }

    /// Drive a non-blocking op to completion on loopback (no reactor in the test).
    fn spin<T>(mut op: impl FnMut() -> io::Result<Option<T>>) -> T {
        for _ in 0..2000 {
            if let Some(value) = op().expect("operation errored") {
                return value;
            }
            sleep(Duration::from_millis(1));
        }
        panic!("operation did not complete on loopback within the timeout");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn loopback_listen_connect_accept_stream() {
        let listener = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("listen on loopback");
        let server_addr = listener.local_addr();
        assert_ne!(server_addr.port(), 0, "an ephemeral port is assigned");

        let mut client = TcpSocket::connect(server_addr, Ipv4Addr::LOCALHOST, |_| Ok(()))
            .expect("connect to loopback");
        let server = spin(|| listener.accept()); // completes the handshake
        client.finish_connect().expect("the connect completed");
        assert!(!client.is_connecting());

        assert!(matches!(
            client.send(b"ping").expect("send"),
            IoStatus::Ready(4)
        ));
        let mut buf = [0u8; 16];
        let n = spin(|| match server.recv(&mut buf)? {
            IoStatus::Ready(0) => panic!("unexpected EOF before the payload"),
            IoStatus::Ready(n) => Ok(Some(n)),
            IoStatus::WouldBlock => Ok(None),
        });
        assert_eq!(&buf[..n], b"ping");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn loopback_send_vectored_concatenates_the_slices() {
        let listener = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("listen on loopback");
        let mut client = TcpSocket::connect(listener.local_addr(), Ipv4Addr::LOCALHOST, |_| Ok(()))
            .expect("connect to loopback");
        let server = spin(|| listener.accept());
        client.finish_connect().expect("the connect completed");

        // A header and a body slice go out in one writev, arriving concatenated.
        let sent = client
            .send_vectored(&[io::IoSlice::new(b"head"), io::IoSlice::new(b"body")])
            .expect("send_vectored");
        assert!(matches!(sent, IoStatus::Ready(8)));
        let mut buf = [0u8; 16];
        let n = spin(|| match server.recv(&mut buf)? {
            IoStatus::Ready(0) => panic!("unexpected EOF before the payload"),
            IoStatus::Ready(n) => Ok(Some(n)),
            IoStatus::WouldBlock => Ok(None),
        });
        assert_eq!(&buf[..n], b"headbody");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn accepted_and_outbound_sockets_disable_nagle() {
        let listener = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("listen on loopback");
        let client = TcpSocket::connect(listener.local_addr(), Ipv4Addr::LOCALHOST, |_| Ok(()))
            .expect("connect");
        let server = spin(|| listener.accept());
        assert!(nodelay(&client), "the outbound socket sets TCP_NODELAY");
        assert!(nodelay(&server), "the accepted socket sets TCP_NODELAY");
    }

    #[test]
    fn nothing_pending_and_a_client_that_died_first_both_read_as_no_connection() {
        for errno in [
            libc::EAGAIN,
            libc::EWOULDBLOCK,
            libc::ECONNABORTED,
            libc::EPROTO,
            libc::ENETDOWN,
            libc::ENETUNREACH,
            libc::EHOSTDOWN,
            libc::EHOSTUNREACH,
            libc::ENOPROTOOPT,
            libc::EOPNOTSUPP,
        ] {
            assert!(
                nothing_to_accept(&io::Error::from_raw_os_error(errno)),
                "errno {errno} leaves no connection to take, so accept reports None"
            );
        }
    }

    #[test]
    fn an_accept_that_leaves_the_connection_queued_reaches_the_caller() {
        // Nothing drained the connection on these, so a level-triggered readiness re-fires on it
        // forever; the caller has to see the error and shed the listener.
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::EINVAL] {
            assert!(
                !nothing_to_accept(&io::Error::from_raw_os_error(errno)),
                "errno {errno} leaves the connection queued and must not be swallowed"
            );
        }
        assert!(!nothing_to_accept(&io::Error::other("not an errno")));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn shutdown_write_half_closes_keeping_the_read_half() {
        let listener = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("listen on loopback");
        let mut client = TcpSocket::connect(listener.local_addr(), Ipv4Addr::LOCALHOST, |_| Ok(()))
            .expect("connect");
        let server = spin(|| listener.accept());
        client.finish_connect().expect("the connect completed");

        // The client shuts down its write half: the server reads EOF.
        client.shutdown_write();
        let mut buf = [0u8; 16];
        let eof = spin(|| match server.recv(&mut buf)? {
            IoStatus::Ready(n) => Ok(Some(n)),
            IoStatus::WouldBlock => Ok(None),
        });
        assert_eq!(
            eof, 0,
            "the server sees EOF after the client's write shutdown"
        );

        // The client's read half stays open: the server's reply still arrives.
        assert!(matches!(
            server.send(b"pong").expect("send"),
            IoStatus::Ready(4)
        ));
        let n = spin(|| match client.recv(&mut buf)? {
            IoStatus::Ready(0) => panic!("the client's read half closed unexpectedly"),
            IoStatus::Ready(n) => Ok(Some(n)),
            IoStatus::WouldBlock => Ok(None),
        });
        assert_eq!(&buf[..n], b"pong");
    }
}
