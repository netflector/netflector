//! Self-pipe signal handling: graceful shutdown (SIGINT/SIGTERM) and an on-demand
//! diagnostics dump (SIGUSR1).
//!
//! A signal arrives at an arbitrary point and its handler may call only
//! async-signal-safe functions, so it cannot touch the reactor (the arena, the
//! logger, allocation are all off-limits). The handler records which kind of signal
//! arrived in an atomic flag and `write`s one byte to a pipe to wake the loop. The
//! pipe's read end is registered with the reactor like any other fd, so the real
//! work (a shutdown, or a counter dump) happens later in normal code, when the loop
//! wakes on it. Needs no per-backend signal support (no `signalfd` / `EVFILT_SIGNAL`);
//! the pipe is just a readable fd.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use libc::c_int;

use super::{Handler, Reactor, ReadyEvent};

/// The signal that requests an on-demand diagnostics dump (the counter summary).
const DUMP_SIGNAL: c_int = libc::SIGUSR1;
/// Every signal a [`SignalGuard`] installs a handler for: the two shutdown signals plus the dump one.
const HANDLED_SIGNALS: [c_int; 3] = [libc::SIGINT, libc::SIGTERM, DUMP_SIGNAL];

/// The write end of the installed self-pipe, or `-1` when none is installed. The
/// handler reads this and writes a byte; [`SignalGuard`] owns the fd and is the
/// only thing that sets this cell, and only one can exist at a time (single
/// reactor, single thread).
static WRITE_FD: AtomicI32 = AtomicI32::new(-1);
/// Set by the handler for a shutdown signal (SIGINT/SIGTERM); the pipe reader consumes it.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
/// Set by the handler for [`DUMP_SIGNAL`]; the pipe reader consumes it.
static DUMP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// The signal handler: async-signal-safe, so it only records intent and wakes the loop.
extern "C" fn on_signal(signum: c_int) {
    // The pipe byte is a pure wakeup; its value carries nothing, the atomic flags carry the intent.
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
}

/// An installed self-pipe with the previous signal dispositions saved. Dropping it
/// restores those dispositions, unpublishes the fd, then closes the write end, in
/// that order, so no signal can reach a handler that points at a closed fd.
pub(crate) struct SignalGuard {
    /// Held only so its `OwnedFd` `Drop` closes the write end when the guard drops.
    _write_fd: OwnedFd,
    saved_actions: [libc::sigaction; HANDLED_SIGNALS.len()],
}

impl SignalGuard {
    /// Create the self-pipe, publish its write end, and install the shutdown and dump handlers.
    /// Returns the guard plus the [`SignalPipe`] handler (owning the read end) to register with the
    /// reactor.
    ///
    /// # Errors
    /// Returns an error if the pipe cannot be created, a handler cannot be
    /// installed, or a guard is already installed.
    pub(crate) fn install() -> io::Result<(Self, SignalPipe)> {
        let (read, write) = self_pipe()?;
        // Publish the write fd for the handler, refusing a second concurrent install.
        if WRITE_FD
            .compare_exchange(-1, write.as_raw_fd(), Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(io::Error::other("signal handlers already installed"));
        }
        // Clear any flag a signal set during a previous guard's teardown window, so it can't leak into
        // this run and turn the first wakeup into a spurious shutdown. No handler is installed yet.
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
        // Order matters: stop signals reaching our handler, then unpublish the fd;
        // `self._write_fd` closes last (after this body), when nothing can touch it.
        restore_handlers(&self.saved_actions);
        WRITE_FD.store(-1, Ordering::SeqCst);
    }
}

/// Reactor handler for the self-pipe read end, which it owns. Drains the pipe and
/// acts on whichever signal flags are set; the bytes themselves carry nothing.
pub(crate) struct SignalPipe {
    read: OwnedFd,
}

impl SignalPipe {
    /// The read-end fd to watch, handed to [`Reactor::register_with_fds`] at install.
    pub(crate) fn read_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }
}

impl Handler for SignalPipe {
    fn on_readable(&mut self, _event: ReadyEvent, reactor: &mut Reactor) {
        // Drain so a level-triggered wait does not keep re-reporting it.
        let mut buf = [0u8; 16];
        let fd = self.read.as_raw_fd();
        // SAFETY: `self.read` is the registered, non-blocking read end; draining
        // stops at EOF (0) or EAGAIN (-1).
        while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        // Shutdown wins if both arrived; a dump on the way out is harmless but pointless.
        if SHUTDOWN_REQUESTED.swap(false, Ordering::Relaxed) {
            // Tells the operator the daemon stopped on a signal, not a crash or self-termination.
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

    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `pipe`/`pipe2` succeeded, so both fds are fresh and owned.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

    #[cfg(target_os = "macos")]
    {
        crate::sys::set_cloexec_nonblock(read.as_raw_fd())?;
        crate::sys::set_cloexec_nonblock(write.as_raw_fd())?;
    }

    Ok((read, write))
}

/// Install [`on_signal`] for every handled signal, returning the previous
/// dispositions to restore later. Rolls back on partial failure.
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
        let rc = unsafe { libc::sigaction(signum, &raw const action, &raw mut saved[i]) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            restore_handlers(&saved[..i]);
            return Err(err);
        }
    }
    Ok(saved)
}

/// Restore previously-saved signal dispositions (best effort, errors ignored).
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
