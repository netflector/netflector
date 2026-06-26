//! The per-direction streaming HTTP/1.1 framer: header scan + authority rewrite (this step), then the
//! zero-copy body framing + `feed` loop (the next step). Built on the parent module's authority parser.

use std::net::SocketAddrV4;

use super::{Authority, parse_authority, strip_prefix_ignore_ascii_case};

/// CRLF, the HTTP line terminator.
const CRLF: &[u8] = b"\r\n";

/// Which side of the splice a framer parses: the start line differs (request-line vs status-line),
/// and only a response can be close-delimited.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Request,
    Response,
}

/// The body framing the header determined — what `feed` (a later step) streams after the header.
/// `Header` doubles as "no body: the message ends at the blank line".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Header,
    BodyContentLength,
    BodyChunked,
    BodyCloseDelimited,
}

/// A malformed message — the proxy maps any variant to drop-and-close.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FramingError {
    /// A `Content-Length` value that isn't a bare non-negative integer.
    MalformedContentLength,
}

/// Per-direction incremental HTTP/1.1 framing with an authority-header rewrite. It buffers only the
/// header — copied into a scratch so it can be rewritten — and (in a later step) forwards the body as
/// a zero-copy slice of the fed input. `rewrite` maps a found device authority to its replacement (or
/// `None` to leave it), supplied per direction by the proxy.
pub(crate) struct HttpFraming {
    rewrite: Box<dyn FnMut(SocketAddrV4) -> Option<SocketAddrV4>>,
    kind: Kind,
    phase: Phase,
    header: Vec<u8>,
    body_remaining: usize,
    chunk_remaining: usize,
}

impl HttpFraming {
    /// A framer for one direction. `rewrite` is called once per `Host` (requests) / `Application-URL`
    /// / `Location` (responses) authority it finds.
    pub(crate) fn new(
        kind: Kind,
        rewrite: Box<dyn FnMut(SocketAddrV4) -> Option<SocketAddrV4>>,
    ) -> Self {
        Self {
            rewrite,
            kind,
            phase: Phase::Header,
            header: Vec::new(),
            body_remaining: 0,
            chunk_remaining: 0,
        }
    }

    /// Rewrite the authority headers of `block` (a complete header block ending in the blank line) into
    /// `self.header`, and set the body phase from its framing. Transforms on copy — each line is
    /// inspected and written to the scratch in one pass, so there is no in-place splice to re-offset.
    ///
    /// # Errors
    /// [`FramingError::MalformedContentLength`] for an unparseable `Content-Length`.
    fn scan_and_rewrite_header(&mut self, block: &[u8]) -> Result<(), FramingError> {
        self.header.clear();
        let mut content_length = None;
        let mut chunked = false;
        let mut status = 0;
        let mut pos = 0;
        let mut first = true;
        while pos < block.len() {
            let line_end = find_crlf(&block[pos..]).map_or(block.len(), |i| pos + i);
            let line = &block[pos..line_end];
            if first {
                if matches!(self.kind, Kind::Response) {
                    status = parse_status_code(line);
                }
                self.copy_line(line);
                first = false;
            } else {
                self.inspect_and_emit(line, &mut content_length, &mut chunked)?;
            }
            pos = line_end + CRLF.len();
        }
        self.set_body_phase(status, content_length, chunked);
        Ok(())
    }

    /// Detect the framing headers (`Content-Length` / `Transfer-Encoding`), rewrite a `Host` /
    /// `Application-URL` / `Location` authority, and emit the (possibly rewritten) line to the scratch.
    fn inspect_and_emit(
        &mut self,
        line: &[u8],
        content_length: &mut Option<usize>,
        chunked: &mut bool,
    ) -> Result<(), FramingError> {
        if let Some(value) = strip_prefix_ignore_ascii_case(line, b"Content-Length:") {
            *content_length = Some(parse_content_length(value)?);
            self.copy_line(line);
            return Ok(());
        }
        if let Some(value) = strip_prefix_ignore_ascii_case(line, b"Transfer-Encoding:") {
            *chunked |= value_has_chunked(value);
            self.copy_line(line);
            return Ok(());
        }
        if let Some((value_off, found)) = rewritable_authority(line) {
            // Call the rewrite (a disjoint field) before borrowing the scratch to emit.
            if let Some(repl) = (self.rewrite)(found.endpoint) {
                let auth_start = value_off + found.offset;
                self.header.extend_from_slice(&line[..auth_start]);
                append_authority(&mut self.header, repl);
                self.header
                    .extend_from_slice(&line[auth_start + found.len..]);
                self.header.extend_from_slice(CRLF);
                return Ok(());
            }
        }
        self.copy_line(line);
        Ok(())
    }

    /// Append `line` and its CRLF to the scratch verbatim.
    fn copy_line(&mut self, line: &[u8]) {
        self.header.extend_from_slice(line);
        self.header.extend_from_slice(CRLF);
    }

    /// Set the body phase from what the header scan found (RFC 7230 §3.3.3 + status-line awareness): a
    /// `1xx`/`204`/`304` response is bodyless regardless of headers; else chunked, then a
    /// `Content-Length` run, else — a request is bodyless, a response is close-delimited (until EOF).
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

/// The byte offset of the first CRLF in `s`, or `None`.
fn find_crlf(s: &[u8]) -> Option<usize> {
    s.windows(2).position(|w| w == CRLF)
}

/// The status code from a response start line (`HTTP/1.1 200 OK` → 200), or 0 if unparseable — 0 is no
/// known bodyless status, so it falls through to the header-driven framing.
fn parse_status_code(line: &[u8]) -> u16 {
    line.split(|&b| b == b' ')
        .nth(1)
        .and_then(|field| std::str::from_utf8(field).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Parse a `Content-Length` value: surrounding whitespace (RFC 7230 OWS) is tolerated, but the rest
/// must be a bare integer — `12abc` is rejected, not truncated to 12.
fn parse_content_length(value: &[u8]) -> Result<usize, FramingError> {
    std::str::from_utf8(value.trim_ascii())
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

/// If `line` is a `Host` / `Application-URL` / `Location` header, parse its authority — returning the
/// value's offset within `line` and the [`Authority`] (whose own offset is relative to that value).
fn rewritable_authority(line: &[u8]) -> Option<(usize, Authority)> {
    let (value, bare) = if let Some(rest) = strip_prefix_ignore_ascii_case(line, b"Host:") {
        (rest, true)
    } else if let Some(rest) = strip_prefix_ignore_ascii_case(line, b"Application-URL:") {
        (rest, false)
    } else if let Some(rest) = strip_prefix_ignore_ascii_case(line, b"Location:") {
        (rest, false)
    } else {
        return None;
    };
    let trimmed = value.trim_ascii_start();
    let value_off = line.len() - trimmed.len();
    Some((value_off, parse_authority(trimmed, bare)?))
}

/// Append `addr` as `host:port` text — the IPv4 [`SocketAddrV4`] `Display` form.
fn append_authority(buf: &mut Vec<u8>, addr: SocketAddrV4) {
    use std::io::Write;
    write!(buf, "{addr}").expect("writing to a Vec is infallible");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framing(
        kind: Kind,
        rewrite: impl FnMut(SocketAddrV4) -> Option<SocketAddrV4> + 'static,
    ) -> HttpFraming {
        HttpFraming::new(kind, Box::new(rewrite))
    }

    #[test]
    fn copies_a_header_verbatim_when_nothing_rewrites() {
        let mut f = framing(Kind::Request, |_| None);
        f.scan_and_rewrite_header(b"GET / HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n")
            .unwrap();
        assert_eq!(f.header, b"GET / HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n");
        assert_eq!(f.phase, Phase::Header); // a GET with no body framing is bodyless
    }

    #[test]
    fn rewrites_the_host_authority_on_a_request() {
        let repl: SocketAddrV4 = "10.1.3.80:36866".parse().unwrap();
        let mut f = framing(Kind::Request, move |_found| Some(repl));
        f.scan_and_rewrite_header(b"GET /apps/YouTube HTTP/1.1\r\nHost: 10.0.0.1:8080\r\n\r\n")
            .unwrap();
        assert_eq!(
            f.header,
            b"GET /apps/YouTube HTTP/1.1\r\nHost: 10.1.3.80:36866\r\n\r\n"
        );
    }

    #[test]
    fn rewrites_location_in_a_chunked_201() {
        let repl: SocketAddrV4 = "10.1.1.5:44747".parse().unwrap();
        let mut f = framing(Kind::Response, move |_| Some(repl));
        f.scan_and_rewrite_header(
            b"HTTP/1.1 201 Created\r\nLocation: http://10.1.3.80:36866/apps/YouTube/run\r\n\
              Transfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            f.header,
            b"HTTP/1.1 201 Created\r\nLocation: http://10.1.1.5:44747/apps/YouTube/run\r\n\
              Transfer-Encoding: chunked\r\n\r\n"
        );
        assert_eq!(f.phase, Phase::BodyChunked); // 201 is NOT special-cased — chunked frames it
    }

    #[test]
    fn content_length_sets_the_body_phase() {
        let mut f = framing(Kind::Response, |_| None);
        f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nContent-Length: 1069\r\n\r\n")
            .unwrap();
        assert_eq!(f.phase, Phase::BodyContentLength);
        assert_eq!(f.body_remaining, 1069);
    }

    #[test]
    fn a_bodyless_status_has_no_body_despite_a_content_length() {
        // 204 is bodyless regardless of headers (RFC 7230 §3.3.3 rule 1).
        let mut f = framing(Kind::Response, |_| None);
        f.scan_and_rewrite_header(b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n")
            .unwrap();
        assert_eq!(f.phase, Phase::Header);
    }

    #[test]
    fn a_response_without_framing_is_close_delimited() {
        let mut f = framing(Kind::Response, |_| None);
        f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n")
            .unwrap();
        assert_eq!(f.phase, Phase::BodyCloseDelimited);
    }

    #[test]
    fn a_request_without_framing_is_bodyless() {
        let mut f = framing(Kind::Request, |_| None);
        f.scan_and_rewrite_header(b"GET / HTTP/1.1\r\n\r\n")
            .unwrap();
        assert_eq!(f.phase, Phase::Header);
    }

    #[test]
    fn malformed_content_length_is_an_error() {
        let mut f = framing(Kind::Response, |_| None);
        assert_eq!(
            f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nContent-Length: 12abc\r\n\r\n"),
            Err(FramingError::MalformedContentLength)
        );
    }

    #[test]
    fn chunked_in_a_coding_list_is_detected() {
        let mut f = framing(Kind::Response, |_| None);
        f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
            .unwrap();
        assert_eq!(f.phase, Phase::BodyChunked);
    }
}
