//! The DIAL application proxy: one per device, fronting the device's HTTP endpoints on the source
//! subnet so its address never leaks. [`connection`] is the per-connection HTTP byte splice,
//! [`proxy`] the per-device reactor handler that accepts clients and opens device connections
//! confined to the target interface ([`egress`]), [`rewrite`] the SSDP-side entry.
//!
//! The proxy's lifetime is owned by the [`DialContext`](crate::dispatch::DialContext) registry, not
//! the proxy itself: the proxy never sees the advertisements that refresh it.

mod connection;
mod egress;
mod proxy;
mod rewrite;

pub(crate) use self::rewrite::{ProxyPlacement, rewrite_location};
