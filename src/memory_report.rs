//! Optional memory-footprint diagnostics, enabled by the `debug_memory_interval_secs` config setting.
//!
//! [`MemoryReporter`] is a timer-only reactor handler that logs the process's resident set size every
//! configured interval; [`run`](crate::run) also emits a baseline at startup and one report at
//! shutdown. The peak RSS comes from `getrusage` (cross-platform); on Linux the current RSS is read from
//! `/proc/self/status`. Heap-arena stats (glibc `mallinfo2`) are intentionally omitted — the static
//! musl build has no equivalent.

use std::time::{Duration, Instant};

use crate::reactor::{Handler, Reactor, ReadyEvent};

/// Peak resident set size in KiB via `getrusage` — no `/proc` needed, so it works on every target.
/// `ru_maxrss` is reported in KiB on Linux and FreeBSD, in bytes on macOS.
fn peak_rss_kib() -> u64 {
    // SAFETY: a zeroed `rusage` is a valid, fully-initialized buffer for `getrusage` to overwrite.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `getrusage` writes a complete `rusage` through the pointer; `RUSAGE_SELF` is a valid `who`.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) } != 0 {
        return 0;
    }
    let maxrss = u64::try_from(usage.ru_maxrss).unwrap_or(0);
    if cfg!(target_os = "macos") {
        maxrss / 1024 // bytes -> KiB
    } else {
        maxrss
    }
}

/// The current resident set (`VmRSS`) in KiB from `/proc/self/status`, or `None` if it can't be read.
#[cfg(target_os = "linux")]
fn current_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmRSS:")?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
    })
}

/// Log one memory report at `info`.
pub(crate) fn log_report() {
    let peak = peak_rss_kib();
    #[cfg(target_os = "linux")]
    match current_rss_kib() {
        Some(rss) => log::info!("memory: rss={rss} KiB, peak={peak} KiB"),
        None => log::info!("memory: peak={peak} KiB (VmRSS unavailable)"),
    }
    #[cfg(not(target_os = "linux"))]
    log::info!("memory: peak={peak} KiB");
}

/// A timer-only reactor handler (it watches no fds) that logs [`log_report`] every `interval`.
pub(crate) struct MemoryReporter {
    interval: Duration,
    next: Instant,
}

impl MemoryReporter {
    /// A reporter whose first report fires `interval` after `now`, then every `interval`.
    pub(crate) fn new(interval: Duration, now: Instant) -> Self {
        Self {
            interval,
            next: now + interval,
        }
    }
}

impl Handler for MemoryReporter {
    /// Never called: the reporter watches no fds.
    fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}

    fn next_deadline(&self) -> Option<Instant> {
        Some(self.next)
    }

    fn on_deadline(&mut self, now: Instant, _reactor: &mut Reactor) {
        log_report();
        self.next = now + self.interval;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peak_rss_is_nonzero_for_the_running_process() {
        // A live process has a non-zero high-water RSS; this also exercises the getrusage path.
        assert!(peak_rss_kib() > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_rss_reads_proc_self_status() {
        assert!(current_rss_kib().is_some_and(|rss| rss > 0));
    }

    #[test]
    fn reporter_schedules_the_next_report_an_interval_out() {
        let interval = Duration::from_secs(30);
        let now = Instant::now();
        let mut reporter = MemoryReporter::new(interval, now);
        assert_eq!(reporter.next_deadline(), Some(now + interval));
        let later = now + interval;
        reporter.on_deadline(later, &mut Reactor::new().unwrap());
        assert_eq!(reporter.next_deadline(), Some(later + interval));
    }
}
