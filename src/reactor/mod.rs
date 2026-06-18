//! Single-threaded reactor: a registration arena dispatched against I/O readiness.
//!
//! Built on a generational-index [`arena`]. Registrations are referred to by a
//! `Copy` key, never a pointer or reference — which is what lets a handler reach
//! back into the reactor (to register or unregister others) without aliasing the
//! storage it lives in. A freed slot bumps its generation, so a stale key fails
//! safe (resolves to nothing) instead of dangling.

pub mod arena;
