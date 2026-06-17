//! ruflector — reflects link-local service traffic (Wake-on-LAN, mDNS, SSDP,
//! and an optional DIAL proxy) between two network interfaces.
//!
//! The behavior lives in this library crate so it stays testable in-process;
//! the binary (`src/main.rs`) is a thin shim over [`run`].

mod error;

pub use error::{Error, Result};

/// Run the reflector to completion.
///
/// `args` is the process argument list with argv[0] already stripped. With a
/// path argument the configuration is read from that TOML file and merged with
/// `REFLECTOR_*` environment variables; with no argument it comes entirely
/// from the environment.
pub fn run(args: &[String]) -> Result<()> {
    match args.first() {
        Some(path) => println!("TODO: load config from {path} (+ REFLECTOR_* env)"),
        None => println!("TODO: load config from environment only"),
    }
    Ok(())
}
