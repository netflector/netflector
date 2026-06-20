//! The wire layer: everything that touches on-the-wire packet formats —
//! IP/UDP checksums and frame building today, MAC addressing and raw capture to
//! come. Higher layers (config, the reflectors) depend on it, not the reverse.

mod checksum;
pub mod frame;
pub mod mac;
