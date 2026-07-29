//! The calling thread's `errno` cell. libc declares the accessor for the BSDs (`__error`) but not for
//! Linux, where both glibc and musl export `__errno_location`.

use libc::c_int;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

/// A pointer to the calling thread's `errno`. Async-signal-safe: the accessor only computes a
/// thread-local address, so a signal handler can save and restore `errno` through it.
pub(crate) fn errno_location() -> *mut c_int {
    #[cfg(target_os = "linux")]
    // SAFETY: the accessor takes no arguments and always returns the thread's errno cell.
    let location = unsafe { __errno_location() };
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    // SAFETY: as above, through libc's declaration.
    let location = unsafe { libc::__error() };
    location
}
