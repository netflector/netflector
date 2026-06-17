//! The crate-wide error type.
//!
//! Every fallible operation returns [`Result<T>`] and `?` propagates failures
//! up to [`crate::run`]. The `Display` text is the user-facing message `main`
//! prints, so its wording is part of the contract — the test suite asserts on
//! substrings of it.

use thiserror::Error;

/// Crate-wide result alias, so signatures read `Result<T>` instead of
/// `Result<T, crate::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while configuring or running the reflector.
///
/// One variant per failure *category*; carry enough context in the payload to
/// render an actionable message. New subsystems add their own variants here
/// (often wrapping a lower-level error with `#[from]`).
#[derive(Debug, Error)]
pub enum Error {
    /// A configuration value was missing, malformed, or contradictory.
    #[error("config: {0}")]
    Config(String),
}
