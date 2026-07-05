//! `libcex` — "libc extended": C library / kernel FFI definitions that are missing from the `libc`
//! crate (for the platforms we build) but should be there, gathered in one place. Elsewhere the code
//! references only `libc::` (standard, upstream-maintained) and `libcex::` (these hand-rolled fills).
//!
//! The split is deliberate — this module does NOT re-export `libc`. The prefix is a provenance signal
//! for `unsafe` FFI: `libc::x` is a definition upstream maintains and vets across platforms, `libcex::x`
//! is one we transcribed from a C header and must scrutinise (layout, value, `cfg`). Keeping them apart
//! also keeps visible pressure to delete a fill once libc ships it. Where libc provides a definition on
//! *some* platform, the hand-rolled arm is anchored to it with a `const _: () = assert!(…)` so it can't
//! silently drift.

mod multicast;

pub(crate) use self::multicast::{GroupReq, MCAST_JOIN_GROUP};
