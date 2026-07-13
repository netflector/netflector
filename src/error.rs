//! The crate-wide error type.
//!
//! Every fallible operation returns [`Result<T>`] and `?` propagates failures up
//! to [`crate::run`]. [`struct@Error`] is opaque: `main` prints its `Display` text to
//! stderr, and tests assert on the subsystems' structured errors directly.

use std::fmt;
use std::io;

use thiserror::Error;

use crate::config::ConfigError;
use crate::reflector::BuildError;

/// Crate-wide result alias, so signatures read `Result<T>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong while configuring or running the reflector.
///
/// Opaque on purpose: callers only print it (`Display`). The structured cause
/// stays crate-internal. Each subsystem keeps its own matchable error type; `?`
/// lifts those in through `From`.
#[derive(Debug)]
pub struct Error(ErrorKind);

/// The private cause behind an [`struct@Error`]: one variant per subsystem.
#[derive(Debug, Error)]
enum ErrorKind {
    /// The command line was misused (see [`UsageError`]).
    #[error(transparent)]
    Usage(#[from] UsageError),
    /// Configuration could not be loaded or failed validation.
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    /// A capture could not be opened (no `CAP_NET_RAW`, or the interface is absent), or its
    /// interface could not be resolved. Built explicitly rather than via the blanket `From`
    /// below, so setup failures read as capture errors, not reactor ones.
    #[error("cannot capture on {iface}: {source}")]
    Capture { iface: String, source: io::Error },
    /// A reflector could not be built from its config (an unknown interface, or a target that
    /// can't currently send a required family).
    #[error("reflector \"{name}\": {source}")]
    Reflector { name: String, source: BuildError },
    /// A reactor or syscall failure. The reactor is currently the crate's only
    /// source of a raw `io::Error`, so the blanket `From` below lands here.
    #[error("reactor: {0}")]
    Reactor(#[from] io::Error),
}

impl Error {
    /// A capture on `iface` could not be set up (open or interface resolution failed).
    pub(crate) fn capture(iface: &str, source: io::Error) -> Self {
        Self(ErrorKind::Capture {
            iface: iface.to_owned(),
            source,
        })
    }

    pub(crate) fn reflector(name: &str, source: BuildError) -> Self {
        Self(ErrorKind::Reflector {
            name: name.to_owned(),
            source,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<ConfigError> for Error {
    fn from(source: ConfigError) -> Self {
        Self(ErrorKind::Config(source))
    }
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Self(ErrorKind::Reactor(source))
    }
}

impl From<UsageError> for Error {
    fn from(source: UsageError) -> Self {
        Self(ErrorKind::Usage(source))
    }
}

/// The command line was misused. The CLI's own matchable error, lifted into [`struct@Error`] by `?`.
#[derive(Debug, Error)]
pub(crate) enum UsageError {
    /// More than the single optional config path was given; the payload is the first extra argument.
    #[error("unexpected extra argument \"{0}\"; try `reflector --help`")]
    TooManyArgs(String),
    /// An option the CLI does not know; the payload is the option as written.
    #[error("unknown option \"{0}\"; try `reflector --help`")]
    UnknownOption(String),
}
