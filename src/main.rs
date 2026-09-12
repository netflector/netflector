//! Thin binary entry point over the `netflector` library.

use std::ffi::OsString;
use std::process::ExitCode;

fn main() -> ExitCode {
    netflector::init_logging();
    // args_os: `args()` panics on a non-UTF-8 argument.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match netflector::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // log, not eprintln: same line format as the rest, and `log_level = "off"` silences
            // it on purpose.
            log::error!("{err}");
            ExitCode::FAILURE
        }
    }
}
