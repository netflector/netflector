//! Per-direction streaming HTTP/1.1 framer: buffers and rewrites the header, then forwards the
//! body as a zero-copy slice of the fed input.

use std::net::SocketAddrV4;

use super::{Authority, parse_authority, strip_prefix_ignore_ascii_case};

const CRLF: &[u8] = b"\r\n";

const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Header-block byte cap, enforced whether or not the block has terminated. The proxy's receive
/// buffer must exceed it (const-asserted there), else the refusal can't fire before the buffer
/// fills and the reader livelocks.
pub(crate) const MAX_HEADER: usize = 2 * 1024;

/// Unterminated-line guard for a chunk-size line, extensions included.
const MAX_CHUNK_LINE: usize = 256;

/// Looser than [`MAX_CHUNK_LINE`]: trailers carry header-like field values.
const MAX_TRAILER_LINE: usize = 1024;

/// Which side of the splice a framer parses; only a response can be close-delimited.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Request,
    Response,
}

/// `Header` doubles as "no body": the message ends at the blank line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Header,
    BodyContentLength,
    BodyChunked,
    BodyChunkedTrailers,
    BodyCloseDelimited,
}

/// A message the proxy can't safely forward; every variant maps to drop-and-close.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FramingError {
    /// A `HEAD` request: its bodyless response may still carry `Content-Length`, indistinguishable
    /// from a body without tracking the request method. DIAL never uses HEAD.
    UnsupportedMethod,
    HeaderTooLong,
    MalformedContentLength,
    /// Differing `Content-Length` values: a request-smuggling vector, unrecoverable per RFC 9112
    /// §6.3. Identical repeats are accepted.
    ConflictingContentLength,
    /// Both `Content-Length` and chunked. RFC 9112 §6.3 lets an intermediary forward after
    /// stripping the `Content-Length`; refused instead.
    ContentLengthWithChunked,
    MalformedChunkSize,
    /// A chunk size whose terminating CRLF would overflow `usize`.
    ChunkSizeTooLarge,
    ChunkLineTooLong,
    TrailerLineTooLong,
}

/// One [`feed`](HttpFraming::feed) call's output. `header` is a view into the framer's scratch,
/// empty while a body streams across feeds; `body` a zero-copy slice of the fed input.
/// `consumed == 0` means an incomplete message: read more and feed again. `application_url` is the
/// first `Application-URL` the header named, *before* the rewrite, reported on the feed that
/// completes the header; the DIAL proxy dials it.
pub(crate) struct Framed<'a> {
    pub(crate) header: &'a [u8],
    pub(crate) body: &'a [u8],
    pub(crate) consumed: usize,
    pub(crate) application_url: Option<SocketAddrV4>,
}

/// Per-direction framer with an authority-header rewrite; see [`feed`](Self::feed).
pub(crate) struct HttpFraming {
    kind: Kind,
    rewrite: RewritePolicy,
    phase: Phase,
    header: Vec<u8>,
    body_remaining: usize,
    chunk_remaining: usize,
}

impl HttpFraming {
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

    /// Feed a contiguous view of the owner's buffered bytes. Each call yields at most one message's
    /// header plus as much of its body as arrived; the owner forwards `header` then `body`, drops
    /// `consumed` bytes, and feeds again until `consumed` is 0. Authority headers (`Host` on
    /// requests, `Application-URL` / `Location` on responses) are rewritten per the
    /// [`RewritePolicy`].
    ///
    /// # Errors
    /// A malformed or over-cap message: see [`FramingError`].
    pub(crate) fn feed<'a>(&'a mut self, input: &'a [u8]) -> Result<Framed<'a>, FramingError> {
        let mut pos = 0;
        let mut header_complete = false;
        let mut application_url = None;
        if matches!(self.phase, Phase::Header) {
            // RFC 9112 §2.2: leading empty lines belong to no message. Skipped before the scan,
            // which would read a pair of them as the header block's end.
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
                });
            };
            if end > MAX_HEADER {
                return Err(FramingError::HeaderTooLong);
            }
            application_url = self.scan_and_rewrite_header(&rest[..end])?;
            pos += end;
            header_complete = true;
        }
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
                    break;
                }
                Phase::BodyCloseDelimited => {
                    pos = input.len(); // forward all; the message ends at EOF (the owner's signal)
                    break;
                }
                Phase::BodyChunked if self.chunk_remaining > 0 => {
                    let take = self.chunk_remaining.min(input.len() - pos);
                    pos += take;
                    self.chunk_remaining -= take;
                    if self.chunk_remaining > 0 {
                        break;
                    }
                }
                Phase::BodyChunked => {
                    let Some(rel) = find_crlf(&input[pos..]) else {
                        if input.len() - pos > MAX_CHUNK_LINE {
                            return Err(FramingError::ChunkLineTooLong);
                        }
                        break;
                    };
                    let size = parse_chunk_size(&input[pos..pos + rel])?;
                    pos += rel + CRLF.len();
                    if size == 0 {
                        self.phase = Phase::BodyChunkedTrailers;
                    } else {
                        // DATA plus its terminating CRLF.
                        self.chunk_remaining = size
                            .checked_add(CRLF.len())
                            .ok_or(FramingError::ChunkSizeTooLarge)?;
                    }
                }
                Phase::BodyChunkedTrailers => {
                    let Some(rel) = find_crlf(&input[pos..]) else {
                        if input.len() - pos > MAX_TRAILER_LINE {
                            return Err(FramingError::TrailerLineTooLong);
                        }
                        break;
                    };
                    let blank = rel == 0;
                    pos += rel + CRLF.len();
                    if blank {
                        self.phase = Phase::Header;
                    }
                }
            }
        }
        Ok(Framed {
            header: if header_complete { &self.header } else { &[] },
            body: &input[body_start..pos],
            consumed: pos,
            application_url,
        })
    }

    /// Rewrite `block` (a complete header block) into the scratch and set the body phase.
    ///
    /// # Errors
    /// A malformed or conflicting framing header, or a `HEAD` request.
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
                // First wins, as a client reads a repeated field (RFC 9110 §5.3): the proxy must
                // dial the same one.
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

    /// Detect the framing headers, rewrite an authority header, and emit the line to the scratch.
    fn inspect_and_emit(
        &mut self,
        line: &[u8],
        content_length: &mut Option<usize>,
        chunked: &mut bool,
    ) -> Result<Option<AuthorityHeader>, FramingError> {
        if let Some(value) = strip_prefix_ignore_ascii_case(line, b"Content-Length:") {
            let n = parse_content_length(value)?;
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

    fn copy_line(&mut self, line: &[u8]) {
        self.header.extend_from_slice(line);
        self.header.extend_from_slice(CRLF);
    }

    /// RFC 7230 §3.3.3 plus the status line: a `1xx`/`204`/`304` response is bodyless whatever the
    /// headers say; else chunked, then `Content-Length`; else a request is bodyless and a response
    /// close-delimited.
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

/// Which authority-bearing header a line is, with the endpoint it named.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AuthorityHeader {
    Host(SocketAddrV4),
    ApplicationUrl(SocketAddrV4),
    Location(SocketAddrV4),
}

/// One optional rewrite target per [`AuthorityHeader`] kind; `None` leaves that kind unchanged.
#[derive(Clone, Copy)]
pub(crate) struct RewritePolicy {
    pub(crate) host: Option<SocketAddrV4>,
    pub(crate) application_url: Option<SocketAddrV4>,
    pub(crate) location: Option<SocketAddrV4>,
}

impl RewritePolicy {
    fn target(&self, header: AuthorityHeader) -> Option<SocketAddrV4> {
        match header {
            AuthorityHeader::Host(_) => self.host,
            AuthorityHeader::ApplicationUrl(_) => self.application_url,
            AuthorityHeader::Location(_) => self.location,
        }
    }
}

fn find_header_end(input: &[u8]) -> Option<usize> {
    input
        .windows(HEADER_TERMINATOR.len())
        .position(|w| w == HEADER_TERMINATOR)
        .map(|i| i + HEADER_TERMINATOR.len())
}

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

fn find_crlf(s: &[u8]) -> Option<usize> {
    s.windows(2).position(|w| w == CRLF)
}

/// 0 when unparseable: no bodyless status matches, so framing falls through to the headers.
fn parse_status_code(line: &[u8]) -> u16 {
    line.split(|&b| b == b' ')
        .nth(1)
        .and_then(|field| std::str::from_utf8(field).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

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

fn value_has_chunked(value: &[u8]) -> bool {
    value
        .split(|&b| b == b',')
        .any(|coding| coding.trim_ascii().eq_ignore_ascii_case(b"chunked"))
}

/// The authority header of `kind`'s side, if `line` is one: the value's offset within `line`, the
/// parsed [`Authority`] (its own offset relative to that value), and which header it was.
///
/// Each header is recognized only on the side that defines it: `Host` on a request,
/// `Application-URL` / `Location` on a response. Otherwise a client could send `Application-URL`
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

fn append_authority(buf: &mut Vec<u8>, addr: SocketAddrV4) {
    use std::io::Write;
    write!(buf, "{addr}").expect("writing to a Vec is infallible");
}

#[cfg(test)]
mod tests;
