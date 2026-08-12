//! Optional memory-footprint diagnostics. `debug_memory_interval_secs` enables a periodic report; a
//! SIGUSR1 [`ControlEvent::Dump`] emits one on demand regardless of that setting.
//!
//! [`MemoryReporter`] is a timer-only reactor handler (watches no fds) that logs resident set size
//! every configured interval and on a control-event dump. [`run`](crate::run) also emits a baseline at
//! startup and one at shutdown when the periodic report is on. Peak RSS comes from `getrusage`
//! (cross-platform); current RSS is read from `/proc/self/status` on Linux, the `kern.proc.pid`
//! sysctl on FreeBSD, and `proc_pidinfo` on macOS. Heap-arena stats (glibc `mallinfo2`) are
//! omitted: the static musl build has no equivalent.

use std::time::{Duration, Instant};

use crate::reactor::{ControlEvent, Handler, Reactor, ReadyEvent};

/// Peak resident set size in KiB via `getrusage`. No `/proc` needed, so it works on every target.
/// `ru_maxrss` is in KiB on Linux and FreeBSD, in bytes on macOS. FreeBSD maintains it by
/// statclock SAMPLING while a thread is on CPU, so a near-idle process the sampler never catches
/// legitimately reads 0 forever; [`log_report`] folds in the process's own observations there.
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

/// The current resident set in KiB from the `kern.proc.pid` sysctl (`ki_rssize`, in pages), or
/// `None` on a sysctl failure or an unexpected reply size: a `kinfo_proc` ABI mismatch reads as
/// absent rather than as garbage from a misaligned field.
#[cfg(target_os = "freebsd")]
fn current_rss_kib() -> Option<u64> {
    // SAFETY: a zeroed `kinfo_proc` is a plain-data buffer for the kernel to overwrite.
    let mut kip: libc::kinfo_proc = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::kinfo_proc>();
    let pid = i32::try_from(std::process::id()).ok()?;
    let mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    // SAFETY: `mib` holds 4 elements, and `kip`/`len` describe a writable buffer of exactly that size.
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            4,
            (&raw mut kip).cast(),
            &raw mut len,
            std::ptr::null(),
            0,
        )
    };
    if rc != 0 {
        log::debug!(
            "memory: kern.proc.pid sysctl failed: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }
    if len != std::mem::size_of::<libc::kinfo_proc>() {
        log::debug!(
            "memory: kern.proc.pid returned {len} bytes, expected {}: kinfo_proc ABI mismatch",
            std::mem::size_of::<libc::kinfo_proc>()
        );
        return None;
    }
    let pages = u64::try_from(kip.ki_rssize).ok()?;
    // SAFETY: `sysconf(_SC_PAGESIZE)` is a pure query; libc serves it from the ELF aux vector,
    // so it is not even a syscall.
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).ok()?;
    Some(pages * page / 1024)
}

/// The current resident set in KiB via `proc_pidinfo(PROC_PIDTASKINFO)` (`pti_resident_size`, in
/// bytes), or `None` when the call fails or fills less than the full struct.
#[cfg(target_os = "macos")]
fn current_rss_kib() -> Option<u64> {
    // SAFETY: a zeroed `proc_taskinfo` is a plain-data buffer for the kernel to overwrite.
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = i32::try_from(std::mem::size_of::<libc::proc_taskinfo>()).ok()?;
    let pid = i32::try_from(std::process::id()).ok()?;
    // SAFETY: `info` is a writable buffer of exactly `size` bytes.
    let rc =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTASKINFO, 0, (&raw mut info).cast(), size) };
    if rc <= 0 {
        log::debug!(
            "memory: proc_pidinfo failed: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }
    if rc != size {
        log::debug!("memory: proc_pidinfo filled {rc} of {size} bytes");
        return None;
    }
    Some(info.pti_resident_size / 1024)
}

/// This process's own RSS high-water mark in KiB, fed by [`log_report`]'s `current_rss_kib`
/// readings: the substitute peak for FreeBSD's sampled-and-possibly-never `ru_maxrss`.
#[cfg(target_os = "freebsd")]
static OBSERVED_PEAK_KIB: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record an RSS observation and return the high-water mark including it.
#[cfg(target_os = "freebsd")]
fn fold_observed(rss: u64) -> u64 {
    let prev = OBSERVED_PEAK_KIB.fetch_max(rss, std::sync::atomic::Ordering::Relaxed);
    prev.max(rss)
}

/// Log one memory report at `info`.
pub(crate) fn log_report() {
    let peak = peak_rss_kib();
    match current_rss_kib() {
        Some(rss) => {
            #[cfg(target_os = "freebsd")]
            let peak = peak.max(fold_observed(rss));
            log::info!("memory: rss={rss} KiB, peak={peak} KiB");
        }
        None => log::info!("memory: peak={peak} KiB (rss unavailable)"),
    }
}

/// A reactor handler (watches no fds) that logs [`log_report`] every `interval` and on a control dump.
/// `interval` is `None` for a dump-only reporter: no periodic timer, but it still dumps on demand.
pub(crate) struct MemoryReporter {
    interval: Option<Duration>,
    /// The next periodic report instant, or `None` when there is no periodic cadence.
    next: Option<Instant>,
}

impl MemoryReporter {
    /// A reporter that logs every `interval` starting `interval` after `now`. When `interval` is
    /// `None`, it logs only on a SIGUSR1 dump.
    pub(crate) fn new(interval: Option<Duration>, now: Instant) -> Self {
        Self {
            interval,
            next: interval.map(|i| now + i),
        }
    }
}

impl Handler for MemoryReporter {
    /// Never called: the reporter watches no fds.
    fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}

    fn next_deadline(&self) -> Option<Instant> {
        self.next
    }

    fn on_deadline(&mut self, now: Instant, _reactor: &mut Reactor) {
        log_report();
        self.next = self.interval.map(|i| now + i);
    }

    /// A SIGUSR1 diagnostics dump: log a memory report on demand, alongside the dispatcher's counters.
    fn on_control(&mut self, event: ControlEvent, _reactor: &mut Reactor) {
        match event {
            ControlEvent::Dump => log_report(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Not on FreeBSD: its sampled maxrss can legitimately be 0 (the tests below cover the
    // substitute path there).
    #[cfg(not(target_os = "freebsd"))]
    #[test]
    #[cfg_attr(miri, ignore = "reads the process resource usage from the kernel")]
    fn peak_rss_is_nonzero_for_the_running_process() {
        // A live process has a non-zero high-water RSS; this also exercises the getrusage path.
        assert!(peak_rss_kib() > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[cfg_attr(miri, ignore = "reads /proc/self/status")]
    fn current_rss_reads_proc_self_status() {
        assert!(current_rss_kib().is_some_and(|rss| rss > 0));
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    #[cfg_attr(miri, ignore = "reads kern.proc from the kernel")]
    fn current_rss_reads_kern_proc() {
        assert!(current_rss_kib().is_some_and(|rss| rss > 0));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[cfg_attr(miri, ignore = "reads the task info from the kernel")]
    fn current_rss_reads_proc_pidinfo() {
        assert!(current_rss_kib().is_some_and(|rss| rss > 0));
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn observed_peak_never_decreases() {
        // The static is shared across tests, so assert only monotonicity, not absolute values.
        let first = fold_observed(1);
        assert!(first >= 1);
        assert!(fold_observed(0) >= first);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real poll backend")]
    fn reporter_schedules_the_next_report_an_interval_out() {
        let interval = Duration::from_secs(30);
        let now = Instant::now();
        let mut reporter = MemoryReporter::new(Some(interval), now);
        assert_eq!(reporter.next_deadline(), Some(now + interval));
        let later = now + interval;
        reporter.on_deadline(later, &mut Reactor::new().unwrap());
        assert_eq!(reporter.next_deadline(), Some(later + interval));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real poll backend")]
    fn dump_only_reporter_keeps_no_deadline() {
        let mut reporter = MemoryReporter::new(None, Instant::now());
        assert_eq!(reporter.next_deadline(), None);
        reporter.on_control(ControlEvent::Dump, &mut Reactor::new().unwrap());
        assert_eq!(reporter.next_deadline(), None);
    }
}
