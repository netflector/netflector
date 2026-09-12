//! Per-direction streaming HTTP/1.1 framer. Buffers and rewrites the header, then forwards the body as
//! a zero-copy slice of the fed input via [`feed`](HttpFraming::feed). Built on the parent module's
//! authority parser.

use std::net::SocketAddrV4;

use super::{Authority, parse_authority, strip_prefix_ignore_ascii_case};

const CRLF: &[u8] = b"\r\n";

const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Header-block byte cap: a header block larger than this is refused whether or not it has terminated,
/// so the limit doesn't depend on TCP segmentation and a peer can't grow the owner's buffer unbounded.
/// The proxy's receive buffer must EXCEED this (a const-assert there), else the over-cap refusal can't
/// fire before the buffer fills and the reader livelocks.
pub(crate) const MAX_HEADER: usize = 2 * 1024;

/// The unterminated-line guard for a single chunk-size line (`1a3\r\n`, plus any chunk extensions).
const MAX_CHUNK_LINE: usize = 256;

/// The unterminated-line guard for a single trailer field line. Looser than a chunk-size line since
/// trailers carry header-like field values.
const MAX_TRAILER_LINE: usize = 1024;

/// Which side of the splice a framer parses: the start line differs (request-line vs status-line),
/// and only a response can be close-delimited.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Request,
    Response,
}

/// The body framing the header determined: what `feed` streams after the header. `Header` doubles as
/// "no body, the message ends at the blank line".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Header,
    BodyContentLength,
    BodyChunked,
    /// After the zero-size chunk: consume trailer field lines until the blank line.
    BodyChunkedTrailers,
    BodyCloseDelimited,
}

/// A message the proxy can't safely forward: malformed, over-cap, or a method whose response it can't
/// delimit. The proxy maps any variant to drop-and-close.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FramingError {
    /// A `HEAD` request. A HEAD response carries no body yet may still send `Content-Length`,
    /// indistinguishable from a real body without tracking the request method, so the proxy refuses HEAD
    /// rather than risk desyncing the keep-alive stream. DIAL itself never uses HEAD.
    UnsupportedMethod,
    /// A header block that never terminated within [`MAX_HEADER`] bytes.
    HeaderTooLong,
    /// A `Content-Length` value that isn't a bare non-negative integer.
    MalformedContentLength,
    /// Multiple `Content-Length` header fields with differing values: RFC 9112 §6.3 treats a message with
    /// conflicting Content-Lengths as unrecoverable (a request-smuggling vector), so the proxy refuses it.
    ConflictingContentLength,
    /// Both a `Content-Length` and a chunked `Transfer-Encoding`. The same §6.3 lets an intermediary
    /// forward one only after stripping the `Content-Length`; forwarding both leaves the proxy and the
    /// device free to disagree about where the message ends. Refused rather than stripped.
    ContentLengthWithChunked,
    /// A chunk-size line that isn't a hex integer.
    MalformedChunkSize,
    /// A chunk size so large that adding its terminating CRLF would overflow `usize`. No legitimate
    /// device emits a near-`2^64` chunk; the unchecked add would otherwise panic (debug) or wrap
    /// (release) and misframe the stream.
    ChunkSizeTooLarge,
    /// A chunk-size line that never terminated within [`MAX_CHUNK_LINE`] bytes.
    ChunkLineTooLong,
    /// A trailer field line that never terminated within [`MAX_TRAILER_LINE`] bytes.
    TrailerLineTooLong,
}

/// One [`feed`](HttpFraming::feed) call's forwardable output: the rewritten `header` (a view into the
/// framer's scratch, empty while a body streams across feeds), the `body` (a zero-copy slice of the fed
/// input, possibly empty), and `consumed`, how many fed bytes to drop. `consumed == 0` means an
/// incomplete message: read more and feed again. It is the routine end of a multi-recv body, not a
/// header-only condition. `application_url` is the device REST base the message's
/// first `Application-URL` named, *before* the rewrite, reported on the feed that completes the header;
/// the DIAL proxy dials it and re-learns it from a later description fetch. Only that header is
/// reported: the others are rewritten per the policy, and nothing dials them.
pub(crate) struct Framed<'a> {
    pub(crate) header: &'a [u8],
    pub(crate) body: &'a [u8],
    pub(crate) consumed: usize,
    pub(crate) application_url: Option<SocketAddrV4>,
}

/// Per-direction incremental HTTP/1.1 framing with an authority-header rewrite. Buffers only the header
/// (copied into a scratch so it can be rewritten) and forwards the body as a zero-copy slice of the fed
/// input. The [`RewritePolicy`] is fixed for the framer's lifetime (the owner's per-direction targets
/// don't change over a connection), so it is stored at construction rather than passed per feed.
pub(crate) struct HttpFraming {
    kind: Kind,
    rewrite: RewritePolicy,
    phase: Phase,
    header: Vec<u8>,
    body_remaining: usize,
    chunk_remaining: usize,
}

impl HttpFraming {
    /// A framer for one direction, rewriting authority headers per `rewrite`.
    pub(crate) fn new(kind: Kind, rewrite: RewritePolicy) -> Self {
        Self {
            kind,
            rewrite,
            phase: Phase::Header,
            header: Vec::new(),
            body_remaining: 0,
            chunk_remaining: 0,
        }
    }

    /// Feed a contiguous view of the owner's buffered bytes; returns the forwardable [`Framed`]. Each
    /// call yields at most one message's header plus as much of its body as arrived; the owner forwards
    /// `header` then `body`, drops `consumed` bytes, and feeds again until `consumed` is 0 (an
    /// incomplete message, read more). `header` borrows the framer's scratch and `body` the input, so
    /// the owner forwards both before advancing past `consumed`.
    ///
    /// Each authority header (`Host` on requests, `Application-URL` / `Location` on responses) is
    /// rewritten per the framer's [`RewritePolicy`]. The target is per-header, so one direction can
    /// send, say, `Application-URL` and `Location` to different listeners.
    ///
    /// # Errors
    /// A malformed or over-cap message: see [`FramingError`].
    pub(crate) fn feed<'a>(&'a mut self, input: &'a [u8]) -> Result<Framed<'a>, FramingError> {
        let mut pos = 0;
        let mut header_complete = false;
        let mut application_url = None;
        if matches!(self.phase, Phase::Header) {
            // RFC 9112 §2.2: empty lines before a start line belong to no message. Skipped here
            // rather than in the scan: find_header_end reads a pair of them as a header block's end.
            while input[pos..].starts_with(CRLF) {
                pos += CRLF.len();
            }
            let rest = &input[pos..];
            let Some(end) = find_header_end(rest) else {
                if rest.len() > MAX_HEADER {
                    return Err(FramingError::HeaderTooLong);
                }
                return Ok(Framed {
                    header: &[],
                    body: &[],
                    consumed: 0,
                    application_url: None,
                }); // incomplete: read more
            };
            if end > MAX_HEADER {
                return Err(FramingError::HeaderTooLong);
            }
            application_url = self.scan_and_rewrite_header(&rest[..end])?;
            pos += end;
            header_complete = true;
        }
        // Forward as much of the body as arrived (a zero-copy slice of `input`), stopping at the message
        // boundary, the end of the input, or an incomplete chunk/trailer line (left for the next feed).
        let body_start = pos;
        loop {
            if pos >= input.len() {
                break;
            }
            match self.phase {
                Phase::Header => break, // the next message starts here; one message per feed
                Phase::BodyContentLength => {
                    let take = self.body_remaining.min(input.len() - pos);
                    pos += take;
                    self.body_remaining -= take;
                    if self.body_remaining == 0 {
                        self.phase = Phase::Header;
                    }
                    break; // a Content-Length body is one contiguous run
                }
                Phase::BodyCloseDelimited => {
                    pos = input.len(); // forward all; the message ends at EOF (the owner's signal)
                    break;
                }
                Phase::BodyChunked if self.chunk_remaining > 0 => {
                    // forward the current chunk's DATA(+CRLF) opaquely
                    let take = self.chunk_remaining.min(input.len() - pos);
                    pos += take;
                    self.chunk_remaining -= take;
                    if self.chunk_remaining > 0 {
                        break; // ran out mid-chunk
                    }
                }
                Phase::BodyChunked => {
                    // at a chunk boundary: parse the next chunk-size line
                    let Some(rel) = find_crlf(&input[pos..]) else {
                        if input.len() - pos > MAX_CHUNK_LINE {
                            return Err(FramingError::ChunkLineTooLong);
                        }
                        break; // incomplete chunk-size line
                    };
                    let size = parse_chunk_size(&input[pos..pos + rel])?;
                    pos += rel + CRLF.len();
                    if size == 0 {
                        self.phase = Phase::BodyChunkedTrailers;
                    } else {
                        // chunk DATA + its terminating CRLF; a near-usize::MAX size (hostile/buggy
                        // device) would overflow the add, so refuse it rather than panic/wrap-and-misframe.
                        self.chunk_remaining = size
                            .checked_add(CRLF.len())
                            .ok_or(FramingError::ChunkSizeTooLarge)?;
                    }
                }
                Phase::BodyChunkedTrailers => {
                    // consume trailer field lines opaquely until the blank line ends the body
                    let Some(rel) = find_crlf(&input[pos..]) else {
                        if input.len() - pos > MAX_TRAILER_LINE {
                            return Err(FramingError::TrailerLineTooLong);
                        }
                        break; // incomplete trailer line
                    };
                    let blank = rel == 0;
                    pos += rel + CRLF.len();
                    if blank {
                        self.phase = Phase::Header;
                    }
                }
            }
        }
        // borrow the scratch only now, after the loop is done mutating `self`
        Ok(Framed {
            header: if header_complete { &self.header } else { &[] },
            body: &input[body_start..pos],
            consumed: pos,
            application_url,
        })
    }

    /// Rewrite the authority headers of `block` (a complete header block ending in the blank line) into
    /// `self.header`, and set the body phase from its framing. Transforms on copy: each line is inspected
    /// and written to the scratch in one pass, so there is no in-place splice to re-offset.
    ///
    /// # Errors
    /// [`FramingError::MalformedContentLength`] for an unparseable `Content-Length`.
    fn scan_and_rewrite_header(
        &mut self,
        block: &[u8],
    ) -> Result<Option<SocketAddrV4>, FramingError> {
        self.header.clear();
        let mut content_length = None;
        let mut chunked = false;
        let mut application_url = None;
        let mut status = 0;
        let mut pos = 0;
        let mut first = true;
        while pos < block.len() {
            let line_end = find_crlf(&block[pos..]).map_or(block.len(), |i| pos + i);
            let line = &block[pos..line_end];
            if first {
                match self.kind {
                    Kind::Response => status = parse_status_code(line),
                    // Refuse HEAD: its bodyless response can't be told from a Content-Length body
                    // without tracking the request method (see FramingError::UnsupportedMethod).
                    Kind::Request if line.starts_with(b"HEAD ") => {
                        return Err(FramingError::UnsupportedMethod);
                    }
                    Kind::Request => {}
                }
                self.copy_line(line);
                first = false;
            } else if let Some(AuthorityHeader::ApplicationUrl(ep)) =
                self.inspect_and_emit(line, &mut content_length, &mut chunked)?
            {
                // First wins: a client reads the first of a repeated field (RFC 9110 §5.3), so the
                // proxy has to dial that same one. Every occurrence is still rewritten above.
                application_url.get_or_insert(ep);
            }
            pos = line_end + CRLF.len();
        }
        if content_length.is_some() && chunked {
            return Err(FramingError::ContentLengthWithChunked);
        }
        self.set_body_phase(status, content_length, chunked);
        Ok(application_url)
    }

    /// Detect the framing headers (`Content-Length` / `Transfer-Encoding`), rewrite a `Host` /
    /// `Application-URL` / `Location` authority, and emit the (possibly rewritten) line to the scratch.
    fn inspect_and_emit(
        &mut self,
        line: &[u8],
        content_length: &mut Option<usize>,
        chunked: &mut bool,
    ) -> Result<Option<AuthorityHeader>, FramingError> {
        if let Some(value) = strip_prefix_ignore_ascii_case(line, b"Content-Length:") {
            let n = parse_content_length(value)?;
            // A second, differing Content-Length is a request-smuggling vector (RFC 9112 §6.3): refuse
            // the message rather than pick a last-wins length. Identical repeats agree, so they're kept.
            if content_length.is_some_and(|prev| prev != n) {
                return Err(FramingError::ConflictingContentLength);
            }
            *content_length = Some(n);
            self.copy_line(line);
            return Ok(None);
        }
        if let Some(value) = strip_prefix_ignore_ascii_case(line, b"Transfer-Encoding:") {
            *chunked |= value_has_chunked(value);
            self.copy_line(line);
            return Ok(None);
        }
        if let Some((value_off, found, header)) = rewritable_authority(line, self.kind) {
            // Rewrite to wherever the policy points this header, and report it either way: the caller
            // keeps the first `Application-URL` and discards the rest.
            if let Some(repl) = self.rewrite.target(header) {
                let auth_start = value_off + found.offset;
                self.header.extend_from_slice(&line[..auth_start]);
                append_authority(&mut self.header, repl);
                self.header
                    .extend_from_slice(&line[auth_start + found.len..]);
                self.header.extend_from_slice(CRLF);
            } else {
                self.copy_line(line);
            }
            return Ok(Some(header));
        }
        self.copy_line(line);
        Ok(None)
    }

    /// Append `line` and its CRLF to the scratch verbatim.
    fn copy_line(&mut self, line: &[u8]) {
        self.header.extend_from_slice(line);
        self.header.extend_from_slice(CRLF);
    }

    /// Set the body phase from what the header scan found (RFC 7230 §3.3.3 + status-line awareness): a
    /// `1xx`/`204`/`304` response is bodyless regardless of headers; else chunked, then a `Content-Length`
    /// run; else a request is bodyless and a response is close-delimited (until EOF).
    fn set_body_phase(&mut self, status: u16, content_length: Option<usize>, chunked: bool) {
        self.body_remaining = 0;
        self.chunk_remaining = 0;
        let bodyless_status =
            matches!(self.kind, Kind::Response) && matches!(status, 100..=199 | 204 | 304);
        self.phase = if bodyless_status {
            Phase::Header
        } else if chunked {
            Phase::BodyChunked
        } else if let Some(n) = content_length {
            if n == 0 {
                Phase::Header
            } else {
                self.body_remaining = n;
                Phase::BodyContentLength
            }
        } else {
            match self.kind {
                Kind::Request => Phase::Header,
                Kind::Response => Phase::BodyCloseDelimited,
            }
        };
    }
}

/// Which authority-bearing header a line is, carrying the endpoint it named, so the framer can rewrite
/// and report it and the owner can act on `ApplicationUrl` alone (the DIAL REST base).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AuthorityHeader {
    Host(SocketAddrV4),
    ApplicationUrl(SocketAddrV4),
    Location(SocketAddrV4),
}

/// Where a framer rewrites each authority header to: one optional target per [`AuthorityHeader`] kind,
/// `None` leaving that kind unchanged. The owner picks the targets (the DIAL proxy points `Host` at the
/// device, `Application-URL` at its REST listener, `Location` at the connection's own listener).
#[derive(Clone, Copy)]
pub(crate) struct RewritePolicy {
    pub(crate) host: Option<SocketAddrV4>,
    pub(crate) application_url: Option<SocketAddrV4>,
    pub(crate) location: Option<SocketAddrV4>,
}

impl RewritePolicy {
    /// The address `header` should be rewritten to under this policy, or `None` to leave it unchanged.
    fn target(&self, header: AuthorityHeader) -> Option<SocketAddrV4> {
        match header {
            AuthorityHeader::Host(_) => self.host,
            AuthorityHeader::ApplicationUrl(_) => self.application_url,
            AuthorityHeader::Location(_) => self.location,
        }
    }
}

/// The length of the header block in `input` (up to and including the terminating blank line), or
/// `None` if the blank line has not arrived yet.
fn find_header_end(input: &[u8]) -> Option<usize> {
    input
        .windows(HEADER_TERMINATOR.len())
        .position(|w| w == HEADER_TERMINATOR)
        .map(|i| i + HEADER_TERMINATOR.len())
}

/// Parse a chunk-size line's hex length, dropping any `;`-delimited chunk extensions.
fn parse_chunk_size(line: &[u8]) -> Result<usize, FramingError> {
    let hex = match line.iter().position(|&b| b == b';') {
        Some(semi) => &line[..semi],
        None => line,
    };
    let hex = hex.trim_ascii();
    // Reject a sign or other non-hex lead (RFC 9112 §7.1 is 1*HEXDIG): from_str_radix tolerates a '+'.
    if !hex.first().is_some_and(u8::is_ascii_hexdigit) {
        return Err(FramingError::MalformedChunkSize);
    }
    let text = std::str::from_utf8(hex).map_err(|_| FramingError::MalformedChunkSize)?;
    usize::from_str_radix(text, 16).map_err(|_| FramingError::MalformedChunkSize)
}

/// The byte offset of the first CRLF in `s`, or `None`.
fn find_crlf(s: &[u8]) -> Option<usize> {
    s.windows(2).position(|w| w == CRLF)
}

/// The status code from a response start line (`HTTP/1.1 200 OK` → 200), or 0 if unparseable. 0 is no
/// known bodyless status, so it falls through to the header-driven framing.
fn parse_status_code(line: &[u8]) -> u16 {
    line.split(|&b| b == b' ')
        .nth(1)
        .and_then(|field| std::str::from_utf8(field).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Parse a `Content-Length` value: surrounding whitespace (RFC 7230 OWS) is tolerated, but the rest
/// must be a bare integer. `12abc` is rejected, not truncated to 12.
fn parse_content_length(value: &[u8]) -> Result<usize, FramingError> {
    let digits = value.trim_ascii();
    // Reject a sign or other non-digit lead (RFC 9110 §8.6 is 1*DIGIT): parse tolerates a '+'.
    if !digits.first().is_some_and(u8::is_ascii_digit) {
        return Err(FramingError::MalformedContentLength);
    }
    std::str::from_utf8(digits)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(FramingError::MalformedContentLength)
}

/// Whether a `Transfer-Encoding` value's coding list contains `chunked` (case-insensitive), e.g.
/// `gzip, chunked`.
fn value_has_chunked(value: &[u8]) -> bool {
    value
        .split(|&b| b == b',')
        .any(|coding| coding.trim_ascii().eq_ignore_ascii_case(b"chunked"))
}

/// If `line` is an authority header of `kind`'s message, parse its authority, returning the value's
/// offset within `line`, the [`Authority`] (the span to rewrite, whose own offset is relative to that
/// value), and the header it was (carrying the endpoint it named).
///
/// Each header is recognized only on the side that defines it: `Host` on a request, `Application-URL`
/// and `Location` on a response. A peer that sends one on the wrong side gets it forwarded verbatim
/// like any other header, never reported. Without that gate a client could send `Application-URL`
/// and name the endpoint the proxy dials for every later REST request.
fn rewritable_authority(line: &[u8], kind: Kind) -> Option<(usize, Authority, AuthorityHeader)> {
    let (value, bare, wrap): (&[u8], bool, fn(SocketAddrV4) -> AuthorityHeader) = match kind {
        Kind::Request => (
            strip_prefix_ignore_ascii_case(line, b"Host:")?,
            true,
            AuthorityHeader::Host,
        ),
        Kind::Response => {
            if let Some(rest) = strip_prefix_ignore_ascii_case(line, b"Application-URL:") {
                (rest, false, AuthorityHeader::ApplicationUrl)
            } else {
                let rest = strip_prefix_ignore_ascii_case(line, b"Location:")?;
                (rest, false, AuthorityHeader::Location)
            }
        }
    };
    let trimmed = value.trim_ascii_start();
    let value_off = line.len() - trimmed.len();
    let found = parse_authority(trimmed, bare)?;
    let header = wrap(found.endpoint);
    Some((value_off, found, header))
}

/// Append `addr` as `host:port` text, the IPv4 [`SocketAddrV4`] `Display` form.
fn append_authority(buf: &mut Vec<u8>, addr: SocketAddrV4) {
    use std::io::Write;
    write!(buf, "{addr}").expect("writing to a Vec is infallible");
}

#[cfg(test)]
mod tests;
