//! Packet dispatch: the layer that wires a [`Capture`] into the reactor.
//!
//! A [`CaptureHandler`] owns one capture and registers with the reactor as a
//! [`Handler`]; when its fd becomes readable, it drains every queued frame and hands
//! each to a sink. The sink is a closure for now — the seam the reflectors will plug
//! into. A frame borrows the capture's reused buffer (valid only for the call), so a
//! sink that needs to keep one must copy it.

use std::os::fd::{AsRawFd, RawFd};

use crate::capture::Capture;
use crate::reactor::{Handler, Reactor};

/// The most frames drained per readable event before yielding to the reactor, so a
/// flooded interface can't starve the others. `AF_PACKET` stops here and the
/// level-triggered wait re-reports the rest; BPF finishes its current userland batch
/// past this, since the wait won't re-fire for those already-read records.
const MAX_FRAMES_PER_EVENT: u32 = 64;

/// Drains a [`Capture`] into a sink on every readable event. The handler owns the
/// capture — so the reactor watches the fd the handler owns — and calls `on_frame`
/// once per captured frame.
pub(crate) struct CaptureHandler<S> {
    capture: Capture,
    on_frame: S,
}

impl<S: FnMut(&[u8])> CaptureHandler<S> {
    /// A handler that hands each frame captured on `capture` to `on_frame`.
    pub(crate) fn new(capture: Capture, on_frame: S) -> Self {
        Self { capture, on_frame }
    }
}

impl<S> AsRawFd for CaptureHandler<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.capture.as_raw_fd()
    }
}

impl<S: FnMut(&[u8])> Handler for CaptureHandler<S> {
    /// Drain the capture on a readable event, handing each frame to the sink. Reads
    /// up to [`MAX_FRAMES_PER_EVENT`] frames, then yields for fairness — for an
    /// `AF_PACKET` socket the level-triggered wait re-reports any frames still queued
    /// in the kernel. The BPF backend is the exception: one `read` pulls a whole
    /// batch into userland and the wait won't re-fire for those records, so the cap
    /// never cuts a batch short (it finishes the current one, then stops). A read
    /// error abandons the batch and logs; the next wait retries. (Fatal-error policy
    /// — unregistering a downed interface — belongs to the dispatcher that owns the
    /// registration key, not here.)
    fn on_readable(&mut self, _reactor: &mut Reactor) {
        let fd = self.capture.as_raw_fd();
        let mut drained = 0u32;
        loop {
            // Stop at the cap to stay fair to other fds — unless BPF still has a
            // userland batch to finish, which the wait won't re-fire for.
            if drained >= MAX_FRAMES_PER_EVENT && !self.capture.has_buffered() {
                break;
            }
            match self.capture.next_frame() {
                Ok(Some(frame)) => {
                    log::trace!("fd {fd}: dispatching {}-byte frame", frame.len());
                    (self.on_frame)(frame);
                    drained += 1;
                }
                Ok(None) => break,
                Err(e) => {
                    log::error!("fd {fd}: capture read failed, abandoning batch: {e}");
                    break;
                }
            }
        }
        if drained > 0 {
            log::trace!("fd {fd}: drained {drained} frame(s)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::open_or_skip;
    use std::cell::Cell;
    use std::net::UdpSocket;
    use std::rc::Rc;

    #[cfg(target_os = "linux")]
    const LOOPBACK: &str = "lo";
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    const LOOPBACK: &str = "lo0";

    // End-to-end bridge: register a CaptureHandler on the loopback interface, send UDP
    // to 127.0.0.1, and drive the reactor — poll_once dispatches the readable capture
    // fd, and the handler drains the looped frames to the sink. Skips without capture
    // access (no BPF / CAP_NET_RAW).
    #[test]
    fn drains_captured_frames_through_the_reactor() -> std::io::Result<()> {
        let Some(capture) = open_or_skip(LOOPBACK, "capture_handler")? else {
            return Ok(());
        };
        let frames = Rc::new(Cell::new(0u32));
        let handler = CaptureHandler::new(capture, {
            let frames = frames.clone();
            move |_frame: &[u8]| frames.set(frames.get() + 1)
        });

        let mut reactor = Reactor::new()?;
        reactor.register(Box::new(handler))?;

        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        let target = receiver.local_addr()?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;

        sender.send_to(b"reflector-bridge-probe", target)?;
        reactor.poll_once(Some(std::time::Duration::from_secs(2)))?;

        assert!(
            frames.get() == 1,
            "the reactor never drained a captured frame"
        );
        Ok(())
    }
}
