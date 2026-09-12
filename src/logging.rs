//! Process-wide logging on the [`log`] facade: one line per record on stderr (stdout is
//! program output), as `<utc> <LEVEL> <target>: <message>`.

use std::cell::RefCell;
use std::fmt::{self, Write as _};
use std::io::Write;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{LevelFilter, Log, Metadata, Record};

use crate::config::LogLevel;

struct StderrLogger;

static LOGGER: StderrLogger = StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        // The trait doesn't guarantee `enabled` runs first.
        if !self.enabled(record.metadata()) {
            return;
        }
        // Format into a reused buffer and write once: stderr is unbuffered, so `write_fmt` would
        // issue a write(2) per fragment.
        thread_local! {
            static LINE: RefCell<String> = const { RefCell::new(String::new()) };
        }
        LINE.with(|line| {
            let mut line = line.borrow_mut();
            line.clear();
            format_record(&mut line, Utc::now(), record);
            std::io::stderr().write_all(line.as_bytes()).ok();
        });
    }

    fn flush(&self) {
        std::io::stderr().flush().ok();
    }
}

fn format_record(line: &mut String, now: Utc, record: &Record) {
    let _ = writeln!(
        line,
        "{now} {:>5} {}: {}",
        record.level(),
        record.target(),
        record.args(),
    );
}

/// A civil UTC date-time; `Display` renders ISO 8601.
#[derive(Clone, Copy)]
struct Utc {
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
}

impl Utc {
    fn now() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        Self::from_unix(secs)
    }

    /// Howard Hinnant's `civil_from_days`, unsigned only: the negative-day branch is unreachable
    /// for post-epoch seconds.
    fn from_unix(secs: u64) -> Self {
        let hour = secs % 86_400 / 3_600;
        let minute = secs % 3_600 / 60;
        let second = secs % 60;

        // Epoch shifted to 0000-03-01 so a 400-year era ends on a leap day.
        let z = secs / 86_400 + 719_468;
        let era = z / 146_097;
        let doe = z - era * 146_097; // [0, 146096]
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        let year = era * 400 + yoe + u64::from(month <= 2);

        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }
}

impl fmt::Display for Utc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second,
        )
    }
}

/// Install the global logger with the default threshold; `set_level` applies the configured
/// one once the configuration is loaded.
///
/// # Panics
/// If called more than once.
pub fn init() {
    log::set_logger(&LOGGER).expect("logging::init called more than once");
    log::set_max_level(LevelFilter::from(LogLevel::default()));
}

pub(crate) fn set_level(level: LogLevel) {
    log::set_max_level(LevelFilter::from(level));
}

/// Like [`log::log!`], but at most once per `window` per call site (not per entry or
/// interface); suppressed calls are counted and disclosed on the next line as ` (N suppressed)`.
macro_rules! log_rate {
    ($level:expr, $window:expr, $($arg:tt)+) => {{
        static LAST: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        static SUPPRESSED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        match $crate::logging::rate_gate(
            &LAST,
            &SUPPRESSED,
            $crate::logging::monotonic_secs(),
            $window,
        ) {
            Some(0) => log::log!($level, $($arg)+),
            Some(suppressed) => log::log!(
                $level,
                "{} ({} suppressed)",
                format_args!($($arg)+),
                suppressed
            ),
            None => {}
        }
    }};
}
pub(crate) use log_rate;

pub(crate) const WARN_WINDOW: Duration = Duration::from_mins(1);

/// The decision behind [`log_rate!`]: `Some(n)` to emit, with `n` suppressed since the last
/// emission; `None` to count this one. Whole-second granularity: a sub-second window emits every
/// call. `u32` because armv5te has no 64-bit atomics; atomics at all only because `static`s
/// demand `Sync`, hence `Relaxed`.
pub(crate) fn rate_gate(
    last: &AtomicU32,
    suppressed: &AtomicU32,
    now_secs: u32,
    window: Duration,
) -> Option<u32> {
    let window_secs = u32::try_from(window.as_secs()).unwrap_or(u32::MAX);
    let last_emit = last.load(Ordering::Relaxed);
    if last_emit == 0 || now_secs.saturating_sub(last_emit) >= window_secs {
        // max(1): elapsed 0 s must not read as "never".
        last.store(now_secs.max(1), Ordering::Relaxed);
        Some(suppressed.swap(0, Ordering::Relaxed))
    } else {
        suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}

/// Seconds since the first call.
pub(crate) fn monotonic_secs() -> u32 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    u32::try_from(START.elapsed().as_secs()).unwrap_or(u32::MAX)
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_gate_emits_first_then_suppresses_within_the_window() {
        let (last, suppressed) = (AtomicU32::new(0), AtomicU32::new(0));
        let window = Duration::from_mins(1);
        // First call emits, with nothing suppressed - even at time 0 (the max(1) offset).
        assert_eq!(rate_gate(&last, &suppressed, 0, window), Some(0));
        // Inside the window: counted, not emitted.
        assert_eq!(rate_gate(&last, &suppressed, 1, window), None);
        assert_eq!(rate_gate(&last, &suppressed, 59, window), None);
        // The window reopens: emit, disclosing the two suppressed calls, and the count resets.
        assert_eq!(rate_gate(&last, &suppressed, 61, window), Some(2));
        assert_eq!(rate_gate(&last, &suppressed, 200, window), Some(0));
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the real clock")]
    fn monotonic_secs_never_decreases() {
        let a = monotonic_secs();
        let b = monotonic_secs();
        assert!(b >= a);
    }

    #[test]
    fn epoch_renders_as_iso() {
        assert_eq!(Utc::from_unix(0).to_string(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn last_second_before_midnight() {
        assert_eq!(Utc::from_unix(86_399).to_string(), "1970-01-01T23:59:59Z");
    }

    #[test]
    fn billennium_is_2001() {
        // 1e9 seconds after the epoch is the well-known 2001-09-09T01:46:40Z.
        assert_eq!(
            Utc::from_unix(1_000_000_000).to_string(),
            "2001-09-09T01:46:40Z"
        );
    }

    #[test]
    fn leap_day_2000_exists() {
        // 2000 is divisible by 400, so it is a leap year and Feb 29 is valid.
        assert_eq!(
            Utc::from_unix(951_782_400).to_string(),
            "2000-02-29T00:00:00Z"
        );
    }

    #[test]
    fn a_record_formats_as_one_stamped_line() {
        let mut line = String::new();
        format_record(
            &mut line,
            Utc::from_unix(0),
            &log::Record::builder()
                .level(log::Level::Info)
                .target("netflector::test")
                .args(format_args!("hello"))
                .build(),
        );
        assert_eq!(line, "1970-01-01T00:00:00Z  INFO netflector::test: hello\n");
    }

    #[test]
    fn log_levels_map_to_filters() {
        assert_eq!(LevelFilter::from(LogLevel::Off), LevelFilter::Off);
        assert_eq!(LevelFilter::from(LogLevel::Error), LevelFilter::Error);
        assert_eq!(LevelFilter::from(LogLevel::Warn), LevelFilter::Warn);
        assert_eq!(LevelFilter::from(LogLevel::Info), LevelFilter::Info);
        assert_eq!(LevelFilter::from(LogLevel::Debug), LevelFilter::Debug);
        assert_eq!(LevelFilter::from(LogLevel::Trace), LevelFilter::Trace);
    }
}
