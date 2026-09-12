//! Self-pipe signal handling: shutdown on SIGINT/SIGTERM, a diagnostics dump on SIGUSR1.
//!
//! The handler may call only async-signal-safe functions, so it sets an atomic flag and
//! writes one byte to a pipe; the reactor watches the read end and does the work in
//! normal code.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use libc::c_int;

use super::{Handler, Reactor, ReadyEvent};
use crate::sys::check;

const DUMP_SIGNAL: c_int = libc::SIGUSR1;
const HANDLED_SIGNALS: [c_int; 3] = [libc::SIGINT, libc::SIGTERM, DUMP_SIGNAL];

/// The self-pipe's write end, or -1 while none is installed.
static WRITE_FD: AtomicI32 = AtomicI32::new(-1);
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static DUMP_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(signum: c_int) {
    // A signal can land between a failed syscall and its errno read; the write below must not
    // clobber errno.
    let location = errno_location();
    // SAFETY: the calling thread's `errno` cell; reading and writing it is async-signal-safe.
    let saved = unsafe { *location };

    if signum == DUMP_SIGNAL {
        DUMP_REQUESTED.store(true, Ordering::Relaxed);
    } else {
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    }
    let fd = WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte: u8 = 0;
        // SAFETY: `write` is async-signal-safe. One byte to the non-blocking
        // self-pipe; a full pipe (EAGAIN) already carries the pending wakeup, so
        // the result is intentionally ignored.
        unsafe {
            libc::write(fd, (&raw const byte).cast(), 1);
        }
    }

    // SAFETY: as above.
    unsafe { *location = saved };
}

/// The thread's `errno` cell. Async-signal-safe: the accessor only computes a thread-local
/// address.
fn errno_location() -> *mut c_int {
    #[cfg(target_os = "linux")]
    // SAFETY: the accessor takes no arguments and always returns the thread's errno cell.
    let location = unsafe { libc::__errno_location() };
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    // SAFETY: as above.
    let location = unsafe { libc::__error() };
    location
}

/// Installed signal handlers plus the previous dispositions; `Drop` restores them.
pub(crate) struct SignalGuard {
    _write_fd: OwnedFd,
    saved_actions: [libc::sigaction; HANDLED_SIGNALS.len()],
}

impl SignalGuard {
    /// # Errors
    /// If the pipe or a handler cannot be set up, or a guard is already installed.
    pub(crate) fn install() -> io::Result<(Self, SignalPipe)> {
        let (read, write) = self_pipe()?;
        WRITE_FD
            .compare_exchange(-1, write.as_raw_fd(), Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| io::Error::other("signal handlers already installed"))?;
        // A signal in a previous guard's teardown window may have left a flag set; clear it before
        // the first wakeup can act on it.
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
        DUMP_REQUESTED.store(false, Ordering::Relaxed);
        let saved = match install_handlers() {
            Ok(saved) => saved,
            Err(e) => {
                WRITE_FD.store(-1, Ordering::SeqCst);
                return Err(e);
            }
        };
        Ok((
            Self {
                _write_fd: write,
                saved_actions: saved,
            },
            SignalPipe { read },
        ))
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        // Handlers off, then unpublish; `_write_fd` closes after this body, when no handler can
        // reach it.
        restore_handlers(&self.saved_actions);
        WRITE_FD.store(-1, Ordering::SeqCst);
    }
}

/// Reactor handler owning the self-pipe's read end.
pub(crate) struct SignalPipe {
    read: OwnedFd,
}

impl SignalPipe {
    pub(crate) fn read_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }
}

impl Handler for SignalPipe {
    fn on_readable(&mut self, _event: ReadyEvent, reactor: &mut Reactor) {
        // Drain, or the level-triggered wait re-reports it.
        let mut buf = [0u8; 16];
        let fd = self.read.as_raw_fd();
        // SAFETY: `self.read` is the registered, non-blocking read end; draining
        // stops at EOF (0) or EAGAIN (-1).
        while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        if SHUTDOWN_REQUESTED.swap(false, Ordering::Relaxed) {
            log::info!("received shutdown signal; stopping");
            reactor.request_shutdown();
        }
        if DUMP_REQUESTED.swap(false, Ordering::Relaxed) {
            log::info!("received SIGUSR1; dumping diagnostics");
            reactor.request_dump();
        }
    }
}

/// A close-on-exec, non-blocking pipe `(read, write)`.
fn self_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let rc = {
        // SAFETY: `pipe2` fills the 2-element `fds` with two fresh owned fds and
        // applies O_CLOEXEC | O_NONBLOCK atomically.
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }
    };
    #[cfg(target_os = "macos")]
    let rc = {
        // SAFETY: `pipe` fills the 2-element `fds` with two fresh owned fds; macOS
        // has no `pipe2`, so the flags are applied with `fcntl` below.
        unsafe { libc::pipe(fds.as_mut_ptr()) }
    };

    check(rc)?;

    // SAFETY: `pipe`/`pipe2` succeeded, so both fds are fresh and owned.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

    #[cfg(target_os = "macos")]
    {
        crate::sys::set_cloexec_nonblock(read.as_raw_fd())?;
        crate::sys::set_cloexec_nonblock(write.as_raw_fd())?;
    }

    Ok((read, write))
}

fn install_handlers() -> io::Result<[libc::sigaction; HANDLED_SIGNALS.len()]> {
    // SAFETY: an all-zero `sigaction` is a valid SIG_DFL disposition we overwrite.
    let mut action: libc::sigaction = unsafe { mem::zeroed() };
    // A function item can't cast straight to an integer; route through a pointer.
    action.sa_sigaction = on_signal as *const () as libc::sighandler_t;
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: `sa_mask` is a valid, owned `sigset_t`.
    unsafe { libc::sigemptyset(&raw mut action.sa_mask) };

    // SAFETY: zeroed `sigaction`s, each filled by its call's oldact out-param.
    let mut saved: [libc::sigaction; HANDLED_SIGNALS.len()] = unsafe { mem::zeroed() };
    for (i, &signum) in HANDLED_SIGNALS.iter().enumerate() {
        // SAFETY: valid signal number with valid act / oldact pointers.
        let installed =
            check(unsafe { libc::sigaction(signum, &raw const action, &raw mut saved[i]) });
        if let Err(err) = installed {
            restore_handlers(&saved[..i]);
            return Err(err);
        }
    }
    Ok(saved)
}

fn restore_handlers(saved: &[libc::sigaction]) {
    for (&signum, action) in HANDLED_SIGNALS.iter().zip(saved) {
        // SAFETY: `action` is a disposition a prior `sigaction` produced.
        unsafe { libc::sigaction(signum, action, ptr::null_mut()) };
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Serializes the tests that call [`SignalGuard::install`]: both touch the process-global
    /// `WRITE_FD` and signal flags, and the harness runs tests on parallel threads.
    static SIGNAL_STATE: Mutex<()> = Mutex::new(());

    #[test]
    #[cfg_attr(all(miri, target_os = "macos"), ignore = "reads real fd flags")]
    fn self_pipe_is_cloexec_and_nonblocking() {
        let (read, write) = self_pipe().unwrap();

        // Non-blocking: reading the empty pipe returns EAGAIN rather than blocking.
        let mut buf = [0u8; 1];
        // SAFETY: read up to 1 byte into `buf` from the valid read-end fd.
        let n = unsafe { libc::read(read.as_raw_fd(), buf.as_mut_ptr().cast(), 1) };
        assert_eq!(n, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );

        // Close-on-exec is set on both ends.
        for fd in [read.as_raw_fd(), write.as_raw_fd()] {
            // SAFETY: F_GETFD reads the descriptor flags of a valid fd.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        }
    }

    // Installs process-global signal handlers, so it is serialized with the other install test via
    // `SIGNAL_STATE`.
    #[test]
    #[cfg_attr(miri, ignore = "installs a real signal handler")]
    fn installed_handler_flags_shutdown_and_dump() {
        let _serialized = SIGNAL_STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (guard, pipe) = SignalGuard::install().unwrap();

        // Our handlers must catch these (set a flag, wake the pipe), not terminate the process:
        // SIGINT flags a shutdown, SIGUSR1 flags a dump.
        // SAFETY: `raise` just delivers a signal to the current process.
        assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
        // SAFETY: as above, deliver SIGUSR1 to ourselves.
        assert_eq!(unsafe { libc::raise(DUMP_SIGNAL) }, 0);

        let mut buf = [0u8; 8];
        // SAFETY: read up to `buf.len()` bytes into `buf` from the valid read-end fd.
        let n = unsafe { libc::read(pipe.read_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        assert!(n >= 1, "each signal wakes the pipe");
        // Consume the flags (as the pipe reader would), asserting each was set.
        assert!(
            SHUTDOWN_REQUESTED.swap(false, Ordering::Relaxed),
            "SIGINT set the shutdown flag"
        );
        assert!(
            DUMP_REQUESTED.swap(false, Ordering::Relaxed),
            "SIGUSR1 set the dump flag"
        );

        // A second install while the first guard holds the write fd is refused.
        assert!(SignalGuard::install().is_err());

        drop(guard); // restores the previous dispositions
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real write(2) failure")]
    fn the_handler_leaves_errno_alone() {
        let _serialized = SIGNAL_STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A pipe's read end refuses a write (EBADF), so the handler's write fails the way it would
        // on a full pipe. No handler is installed: `on_signal` is called directly.
        let (read, _write) = self_pipe().unwrap();
        let previous = WRITE_FD.swap(read.as_raw_fd(), Ordering::SeqCst);

        let location = errno_location();
        // SAFETY: the calling thread's errno cell.
        let observed = unsafe {
            *location = libc::EEXIST;
            on_signal(DUMP_SIGNAL);
            *location
        };

        WRITE_FD.store(previous, Ordering::SeqCst);
        DUMP_REQUESTED.store(false, Ordering::Relaxed);
        assert_eq!(observed, libc::EEXIST);
    }

    #[test]
    #[cfg_attr(miri, ignore = "installs a real signal handler")]
    fn install_clears_a_stale_signal_flag() {
        let _serialized = SIGNAL_STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A flag a signal set during a prior run's teardown window must not survive into the next
        // install, or the first wakeup would act on it (e.g. a spurious shutdown).
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
        DUMP_REQUESTED.store(true, Ordering::Relaxed);
        let (guard, _pipe) = SignalGuard::install().unwrap();
        assert!(
            !SHUTDOWN_REQUESTED.load(Ordering::Relaxed),
            "install clears a stale shutdown flag"
        );
        assert!(
            !DUMP_REQUESTED.load(Ordering::Relaxed),
            "install clears a stale dump flag"
        );
        drop(guard);
    }
}
