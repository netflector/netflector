//! A fixed-capacity byte buffer with a FIFO cursor pair: appended (or written through [`io::Write`])
//! at the back, consumed from the front. It holds one direction of a proxied TCP stream, and the
//! reused scratch a rewritten SSDP datagram is built in. The backing store is allocated on first use,
//! so a buffer that never fills never allocates. Capacity is fixed: an [`append`](StreamBuffer::append)
//! past it is an [`Overflow`] (the proxy drops-and-closes rather than let a stuck peer pin unbounded
//! memory), a [`write`](io::Write::write) past it is a short write, so `write_all` reports `WriteZero`.

use std::io;

/// From [`StreamBuffer::append`] when the data won't fit even after reclaiming the consumed prefix.
#[derive(Debug)]
pub(crate) struct Overflow;

/// A bounded FIFO byte buffer: append at `filled`, consume from `consumed`, live bytes in between.
pub(crate) struct StreamBuffer {
    /// `None` until the first write; `capacity` bytes once set.
    storage: Option<Box<[u8]>>,
    capacity: usize,
    filled: usize,
    /// The live region is `storage[consumed..filled]`.
    consumed: usize,
}

impl StreamBuffer {
    /// Holds at most `cap` live bytes.
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            storage: None,
            capacity: cap,
            filled: 0,
            consumed: 0,
        }
    }

    /// The live bytes: written, not yet consumed.
    pub(crate) fn pending(&self) -> &[u8] {
        self.storage
            .as_deref()
            .map_or(&[], |storage| &storage[self.consumed..self.filled])
    }

    pub(crate) fn len(&self) -> usize {
        self.filled - self.consumed
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.filled == self.consumed
    }

    /// Append `data` whole, reclaiming the consumed prefix first if the tail can't hold it. `Err`
    /// (buffer unchanged) if the live bytes plus `data` would exceed capacity.
    pub(crate) fn append(&mut self, data: &[u8]) -> Result<(), Overflow> {
        if self.len() + data.len() > self.capacity {
            return Err(Overflow);
        }
        self.push(data);
        Ok(())
    }

    /// The free space at the back, to receive into in place; [`commit`](Self::commit) marks how many
    /// bytes landed. Reclaims the consumed prefix first when the tail is exhausted, so the whole spare
    /// capacity is offered as one slice. Empty only when full of live bytes: the caller then holds an
    /// unframable, over-long message.
    pub(crate) fn free_tail_mut(&mut self) -> &mut [u8] {
        if self.filled == self.capacity && self.consumed > 0 {
            self.compact();
        }
        let filled = self.filled;
        &mut self.storage_mut()[filled..]
    }

    /// Mark `n` bytes received into [`free_tail_mut`](Self::free_tail_mut) as live.
    pub(crate) fn commit(&mut self, n: usize) {
        debug_assert!(self.filled + n <= self.capacity, "commit past the capacity");
        self.filled += n;
    }

    /// Drop the first `n` live bytes. Both cursors reset to the front once the buffer empties, so a
    /// fully-drained buffer offers its whole capacity again.
    pub(crate) fn consume(&mut self, n: usize) {
        debug_assert!(
            self.consumed + n <= self.filled,
            "consume past the filled bytes"
        );
        self.consumed += n;
        // `>=`, not `==`: the assert is compiled out in release, so an over-consume must still reset
        // cleanly rather than leave `consumed > filled`, which would underflow `len`.
        if self.consumed >= self.filled {
            self.consumed = 0;
            self.filled = 0;
        }
    }

    /// Drop every byte (keeping the allocation), to build the next message from the front.
    pub(crate) fn clear(&mut self) {
        self.filled = 0;
        self.consumed = 0;
    }

    /// Copy `data`, which the caller has checked fits, to the back.
    fn push(&mut self, data: &[u8]) {
        if data.is_empty() {
            return; // avoid forcing the lazy allocation for a no-op
        }
        if self.filled + data.len() > self.capacity {
            self.compact();
        }
        let filled = self.filled;
        self.storage_mut()[filled..filled + data.len()].copy_from_slice(data);
        self.filled = filled + data.len();
    }

    fn storage_mut(&mut self) -> &mut [u8] {
        let capacity = self.capacity;
        &mut self
            .storage
            .get_or_insert_with(|| vec![0u8; capacity].into_boxed_slice())[..]
    }

    /// Slide the live bytes to the front, dropping the consumed prefix.
    fn compact(&mut self) {
        if let Some(storage) = &mut self.storage {
            storage.copy_within(self.consumed..self.filled, 0);
        }
        self.filled -= self.consumed;
        self.consumed = 0;
    }
}

impl io::Write for StreamBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(self.capacity - self.len());
        self.push(&data[..n]);
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
    fn new_buffer_is_empty() {
        let b = StreamBuffer::with_capacity(8);
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
        assert_eq!(b.pending(), b"");
    }

    #[test]
    fn append_then_pending_returns_the_bytes() {
        let mut b = StreamBuffer::with_capacity(8);
        b.append(b"abc").unwrap();
        assert_eq!(b.pending(), b"abc");
        assert_eq!(b.len(), 3);
        assert!(!b.is_empty());
    }

    #[test]
    fn consume_advances_the_front() {
        let mut b = StreamBuffer::with_capacity(8);
        b.append(b"abcd").unwrap();
        b.consume(2);
        assert_eq!(b.pending(), b"cd");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn consuming_everything_empties_and_offers_full_capacity_again() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"abcd").unwrap();
        b.consume(4);
        assert!(b.is_empty());
        // The cursors reset, so the whole capacity is available, not just the tail.
        b.append(b"wxyz").unwrap();
        assert_eq!(b.pending(), b"wxyz");
    }

    #[test]
    fn append_compacts_to_reclaim_consumed_space() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"ab").unwrap();
        b.consume(2); // consumed=2, filled=2: the tail has only 2 free bytes
        // 3 bytes don't fit the tail but do fit after reclaiming the consumed prefix.
        b.append(b"xyz").unwrap();
        assert_eq!(b.pending(), b"xyz");
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn fills_to_exactly_capacity() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"abcd").unwrap();
        assert_eq!(b.len(), 4);
        assert!(b.append(b"e").is_err()); // one more overflows
    }

    #[test]
    fn append_past_capacity_overflows_and_leaves_the_buffer_intact() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"abc").unwrap();
        assert!(b.append(b"de").is_err()); // 3 + 2 > 4
        // The failed append didn't disturb the live bytes.
        assert_eq!(b.pending(), b"abc");
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn append_of_empty_data_is_a_noop() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"").unwrap();
        assert!(b.is_empty());
        b.append(b"ab").unwrap();
        b.append(b"").unwrap();
        assert_eq!(b.pending(), b"ab");
    }

    #[test]
    fn free_tail_mut_offers_the_spare_capacity_and_commit_fills_it() {
        let mut b = StreamBuffer::with_capacity(8);
        b.append(b"ab").unwrap();
        let tail = b.free_tail_mut();
        assert_eq!(tail.len(), 6);
        tail[..3].copy_from_slice(b"xyz");
        b.commit(3);
        assert_eq!(b.pending(), b"abxyz");
    }

    #[test]
    fn free_tail_mut_compacts_when_the_tail_is_exhausted() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"abcd").unwrap(); // tail full
        b.consume(2); // live "cd"; tail exhausted but 2 bytes reclaimable
        let tail = b.free_tail_mut(); // compacts: "cd" slides to the front
        assert_eq!(tail.len(), 2);
        tail.copy_from_slice(b"ef");
        b.commit(2);
        assert_eq!(b.pending(), b"cdef");
    }

    #[test]
    fn free_tail_mut_is_empty_when_full_of_live_bytes() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"abcd").unwrap();
        assert!(b.free_tail_mut().is_empty()); // no consumed prefix to reclaim
    }

    #[test]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "consume's guard is a debug_assert!, compiled out in release"
    )]
    #[should_panic(expected = "consume past the filled bytes")]
    fn consuming_past_the_filled_bytes_panics() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"ab").unwrap();
        b.consume(3); // only 2 are filled
    }

    #[test]
    fn writes_then_reads_the_written_prefix() {
        let mut b = StreamBuffer::with_capacity(8);
        b.write_all(b"abc").unwrap();
        assert_eq!(b.pending(), b"abc");
        write!(b, "{}", 42).unwrap();
        assert_eq!(b.pending(), b"abc42");
    }

    #[test]
    fn clear_resets_but_keeps_writing_from_the_front() {
        let mut b = StreamBuffer::with_capacity(8);
        b.write_all(b"abc").unwrap();
        b.clear();
        assert_eq!(b.pending(), b"");
        b.write_all(b"xy").unwrap();
        assert_eq!(b.pending(), b"xy");
    }

    #[test]
    fn write_past_capacity_is_a_short_write() {
        let mut b = StreamBuffer::with_capacity(4);
        // The 4 fit-able bytes are written even though the overflow makes `write_all` fail.
        assert!(b.write_all(b"abcde").is_err());
        assert_eq!(b.pending(), b"abcd");
    }

    #[test]
    fn writing_to_a_full_buffer_makes_no_progress() {
        let mut b = StreamBuffer::with_capacity(3);
        b.write_all(b"abc").unwrap();
        assert_eq!(b.write(b"d").unwrap(), 0);
        assert!(b.write_all(b"d").is_err());
        assert_eq!(b.pending(), b"abc");
    }
}
