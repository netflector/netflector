//! FreeBSD socket options missing from `libc`.

/// `SO_RERROR`: make a receive-buffer overflow surface as an error (`ENOBUFS` on the next recv) instead
/// of being silently dropped. FreeBSD 13.0+; absent from `libc` as of 0.2.186. Value from
/// `sys/sys/socket.h`.
pub(crate) const SO_RERROR: libc::c_int = 0x0002_0000;
