//! Binary entry point — kept thin on purpose.
//!
//! All real logic lives in the `ruflector` library crate so it can be tested
//! without spawning a process. `main` installs the process-global logger,
//! collects the environment, and turns a [`ruflector::Result`] into a process
//! exit code: on failure it prints the error and exits non-zero.

use std::process::ExitCode;

fn main() -> ExitCode {
    ruflector::init_logging();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match ruflector::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ruflector: {err}");
            ExitCode::FAILURE
        }
    }
}
