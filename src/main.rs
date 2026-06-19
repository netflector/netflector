//! Binary entry point — kept thin on purpose.
//!
//! All real logic lives in the `reflector` library crate so it can be tested
//! without spawning a process. `main` installs the process-global logger,
//! collects the environment, and turns a [`reflector::Result`] into a process
//! exit code: on failure it prints the error and exits non-zero.

use std::process::ExitCode;

fn main() -> ExitCode {
    reflector::init_logging();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match reflector::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("reflector: {err}");
            ExitCode::FAILURE
        }
    }
}
