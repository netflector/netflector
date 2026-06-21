//! Readiness backend: an OS-uniform [`Poller`] over the platform's readiness
//! syscalls. A wait reports which registered fds are ready, each tagged with the
//! reactor [`Key`] handed to the kernel, so dispatch needs no fd-to-handler side
//! table. The kqueue backend (macOS/FreeBSD) is implemented; epoll (Linux) follows.

use super::{Key, Readiness};

// The reactor re-exports and drives `kqueue::Poller` once it is wired in; for now
// the backend stands alone with its own tests.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod kqueue;

/// One ready fd from a [`Poller`] wait: the [`Key`] it was registered under and
/// what it is ready for.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PollEvent {
    pub key: Key,
    pub readiness: Readiness,
}
