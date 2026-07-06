//! Thin binary entry point.
//!
//! All logic lives in the `reflector` library so it can be tested without
//! spawning a process. `main` installs the logger, collects the environment,
//! and turns a [`reflector::Result`] into an exit code: on failure it logs the
//! error and exits non-zero.

use std::process::ExitCode;

fn main() -> ExitCode {
    reflector::init_logging();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match reflector::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Log facade, not eprintln, so a fatal error reads like every other line
            // (timestamp + level). `log_level = "off"` silences it, which is that
            // setting's intent.
            log::error!("{err}");
            ExitCode::FAILURE
        }
    }
}
