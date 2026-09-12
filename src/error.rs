//! The crate-wide error type. [`struct@Error`] is opaque: `main` prints its `Display` text;
//! tests match the subsystems' structured errors.

use std::fmt;
use std::io;

use thiserror::Error;

use crate::config::ConfigError;
use crate::reflector::BuildError;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong while configuring or running netflector. Opaque: callers only
/// print it.
#[derive(Debug)]
pub struct Error(ErrorKind);

#[derive(Debug, Error)]
enum ErrorKind {
    #[error(transparent)]
    Usage(#[from] UsageError),
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    /// Built via [`Error::capture`], not the blanket `From<io::Error>`, so a setup failure
    /// doesn't read as a reactor error.
    #[error("cannot capture on {iface}: {source}")]
    Capture { iface: String, source: io::Error },
    #[error("reflector \"{name}\": {source}")]
    Reflector { name: String, source: BuildError },
    /// Where the blanket `From<io::Error>` lands; the reactor is the only raw `io::Error`
    /// source.
    #[error("reactor: {0}")]
    Reactor(#[from] io::Error),
}

impl Error {
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

/// The command line was misused.
#[derive(Debug, Error)]
pub(crate) enum UsageError {
    #[error("unexpected extra argument \"{0}\"; try `netflector --help`")]
    TooManyArgs(String),
    #[error("unknown option \"{0}\"; try `netflector --help`")]
    UnknownOption(String),
}
