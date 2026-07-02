//! A write-only, fixed-capacity byte sink over uninitialized storage: filled front-to-back through
//! [`io::Write`], then read back as the written prefix via [`filled`](UninitBuf::filled). Backed by a
//! `Box<[MaybeUninit<u8>]>` allocated on first write and never zero-filled — only the written
//! `storage[..filled]` region is ever read. A write past the capacity is a short write (so
//! [`write_all`](io::Write::write_all) returns `WriteZero`), letting the caller treat "didn't fit" as a
//! signal rather than silently truncating. Reuse across messages with [`clear`](UninitBuf::clear).
//!
//! All of the `unsafe` uninitialized-memory handling lives here, behind a safe interface — callers only
//! see `io::Write`, `clear`, and `filled`.

use std::io;
use std::mem::MaybeUninit;
use std::{ptr, slice};

/// A fixed-capacity byte sink over uninitialized, lazily-allocated storage; see the module doc.
pub(crate) struct UninitBuf {
    /// The backing store, `None` until the first write; `capacity` bytes once set.
    storage: Option<Box<[MaybeUninit<u8>]>>,
    capacity: usize,
    /// Bytes written; the initialized (and readable) region is `storage[..filled]`.
    filled: usize,
}

impl UninitBuf {
    /// Holds at most `cap` bytes. The backing store is allocated — uninitialized, never zero-filled —
    /// on the first write, so an unused buffer costs nothing.
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            storage: None,
            capacity: cap,
            filled: 0,
        }
    }

    /// Discard the written bytes (keeping the allocation) to build the next message.
    pub(crate) fn clear(&mut self) {
        self.filled = 0;
    }

    /// The bytes written since the last [`clear`](Self::clear).
    pub(crate) fn filled(&self) -> &[u8] {
        match &self.storage {
            // SAFETY: `[..filled]` is exactly the region `write` wrote, so it is initialized;
            // `MaybeUninit<u8>` and `u8` share layout.
            Some(storage) => unsafe {
                slice::from_raw_parts(storage.as_ptr().cast::<u8>(), self.filled)
            },
            None => &[],
        }
    }
}

impl io::Write for UninitBuf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(self.capacity - self.filled);
        let storage = self
            .storage
            .get_or_insert_with(|| Box::new_uninit_slice(self.capacity));
        // SAFETY: `n <= capacity - filled`, so `storage[filled..filled + n]` is in bounds. `data` is a
        // shared borrow and `storage` lives behind `&mut self`, so they can't overlap. Layouts match.
        unsafe {
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                storage.as_mut_ptr().add(self.filled).cast::<u8>(),
                n,
            );
        }
        self.filled += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn writes_then_reads_the_filled_prefix() {
        let mut b = UninitBuf::with_capacity(8);
        b.write_all(b"abc").unwrap();
        assert_eq!(b.filled(), b"abc");
        write!(b, "{}", 42).unwrap();
        assert_eq!(b.filled(), b"abc42");
    }

    #[test]
    fn clear_resets_but_keeps_writing_from_the_front() {
        let mut b = UninitBuf::with_capacity(8);
        b.write_all(b"abc").unwrap();
        b.clear();
        assert_eq!(b.filled(), b"");
        b.write_all(b"xy").unwrap();
        assert_eq!(b.filled(), b"xy");
    }

    #[test]
    fn unwritten_buffer_is_empty_and_unallocated() {
        let b = UninitBuf::with_capacity(8);
        assert_eq!(b.filled(), b"");
    }

    #[test]
    fn write_past_capacity_is_a_short_write() {
        let mut b = UninitBuf::with_capacity(4);
        // The 4 fit-able bytes land before the overflow makes `write_all` fail rather than truncate.
        assert!(b.write_all(b"abcde").is_err());
        assert_eq!(b.filled(), b"abcd");
    }

    #[test]
    fn writing_to_a_full_buffer_makes_no_progress() {
        let mut b = UninitBuf::with_capacity(3);
        b.write_all(b"abc").unwrap();
        assert_eq!(b.write(b"d").unwrap(), 0);
        assert!(b.write_all(b"d").is_err());
        assert_eq!(b.filled(), b"abc");
    }
}
