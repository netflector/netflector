//! The reflectors: per-protocol packet handlers that re-emit matched traffic on the opposite
//! interface. Each implements the dispatcher's `PacketHandler` and is registered by `run()`
//! from config. Wake-on-LAN is the first; mDNS and SSDP follow.

pub(crate) mod wol;
