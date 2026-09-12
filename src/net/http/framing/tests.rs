
use super::*;

impl RewritePolicy {
    /// A no-op policy: every authority header passes through unchanged. Tests only; the proxy
    /// always frames with a live policy.
    pub(crate) const NONE: Self = Self {
        host: None,
        application_url: None,
        location: None,
    };
}

/// A rewrite policy that sends every authority header to `repl`.
fn rewrite_all(repl: SocketAddrV4) -> RewritePolicy {
    RewritePolicy {
        host: Some(repl),
        application_url: Some(repl),
        location: Some(repl),
    }
}

#[test]
fn copies_a_header_verbatim_when_nothing_rewrites() {
    let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
    f.scan_and_rewrite_header(b"GET / HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n")
        .unwrap();
    assert_eq!(f.header, b"GET / HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n");
    assert_eq!(f.phase, Phase::Header); // a GET with no body framing is bodyless
}

#[test]
fn rewrites_the_host_authority_on_a_request() {
    let repl: SocketAddrV4 = "10.1.3.80:36866".parse().unwrap();
    let mut f = HttpFraming::new(Kind::Request, rewrite_all(repl));
    f.scan_and_rewrite_header(b"GET /apps/YouTube HTTP/1.1\r\nHost: 10.0.0.1:8080\r\n\r\n")
        .unwrap();
    assert_eq!(
        f.header,
        b"GET /apps/YouTube HTTP/1.1\r\nHost: 10.1.3.80:36866\r\n\r\n"
    );
}

#[test]
fn refuses_a_head_request_behind_a_leading_empty_line() {
    // The device ignores the empty line and answers the HEAD, so the proxy must see what it sees.
    let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
    assert_eq!(
        f.feed(b"\r\nHEAD /dd.xml HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n")
            .err(),
        Some(FramingError::UnsupportedMethod)
    );
}

#[test]
fn does_not_forward_leading_empty_lines() {
    // Normalized away, so the device never has to decide whether to tolerate it.
    let input = b"\r\n\r\nGET /dd.xml HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n";
    let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
    let framed = f.feed(input).unwrap();
    assert_eq!(
        framed.header,
        b"GET /dd.xml HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n"
    );
    assert_eq!(
        framed.consumed,
        input.len(),
        "the skipped bytes are consumed too"
    );
}

#[test]
fn reads_the_status_line_behind_leading_empty_lines() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    f.feed(b"\r\n\r\n\r\nHTTP/1.1 204 No Content\r\nContent-Length: 100\r\n\r\n")
        .unwrap();
    assert_eq!(f.phase, Phase::Header, "204 is bodyless despite the length");
}

#[test]
fn refuses_a_head_request() {
    // A HEAD response is bodyless but may still carry Content-Length, which would desync the
    // keep-alive stream, so the proxy refuses HEAD outright (DIAL never uses it).
    let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
    assert_eq!(
        f.scan_and_rewrite_header(b"HEAD /dd.xml HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n"),
        Err(FramingError::UnsupportedMethod)
    );
    // A normal request method still frames.
    let mut g = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
    assert!(
        g.scan_and_rewrite_header(b"GET /dd.xml HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n")
            .is_ok()
    );
}

#[test]
fn rejects_conflicting_content_lengths() {
    // Two differing Content-Length headers are a smuggling vector; refuse rather than last-wins.
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    assert_eq!(
        f.scan_and_rewrite_header(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 100\r\n\r\n"
        ),
        Err(FramingError::ConflictingContentLength)
    );
    // Identical repeats agree on the framing, so they are tolerated.
    let mut g = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    assert!(
        g.scan_and_rewrite_header(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n"
        )
        .is_ok()
    );
}

#[test]
fn rejects_a_signed_length_or_chunk_size() {
    // Rust's integer parsing accepts a leading '+', but the RFC grammars are 1*DIGIT / 1*HEXDIG.
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    assert_eq!(
        f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n"),
        Err(FramingError::MalformedContentLength)
    );
    assert_eq!(
        parse_chunk_size(b"+ff"),
        Err(FramingError::MalformedChunkSize)
    );
    assert_eq!(parse_chunk_size(b"ff"), Ok(255)); // a bare hex size still parses
}

#[test]
fn rejects_an_over_cap_header_even_when_terminated() {
    // The cap must not depend on TCP segmentation: a terminated header block over MAX_HEADER is
    // refused just like an unterminated one, so a coalesced recv can't slip a huge header through.
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    let mut msg = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
    msg.resize(msg.len() + MAX_HEADER, b'a');
    msg.extend_from_slice(b"\r\n\r\n");
    assert!(matches!(f.feed(&msg), Err(FramingError::HeaderTooLong)));
}

#[test]
fn reports_the_application_url_endpoint_while_rewriting_it() {
    let repl: SocketAddrV4 = "10.1.1.5:44747".parse().unwrap();
    let mut f = HttpFraming::new(Kind::Response, rewrite_all(repl));
    let framed = f
            .feed(
                b"HTTP/1.1 200 OK\r\nApplication-URL: http://10.0.0.7:8008/apps\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
    // The owner learns the device's REST base (to dial it) even as the header is rewritten to the proxy.
    assert_eq!(
        framed.application_url,
        Some("10.0.0.7:8008".parse().unwrap())
    );
    assert_eq!(
            framed.header,
            &b"HTTP/1.1 200 OK\r\nApplication-URL: http://10.1.1.5:44747/apps\r\nContent-Length: 0\r\n\r\n"[..]
        );
    // A Location reports as its own variant (a launched-instance child URL), which the owner (acting
    // on Application-URL only) ignores.
    let mut g = HttpFraming::new(Kind::Response, rewrite_all(repl));
    let framed = g
            .feed(
                b"HTTP/1.1 201 Created\r\nLocation: http://10.0.0.7:8008/apps/X/run\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
    // Rewritten per the policy, but never reported: nothing dials a Location.
    assert_eq!(framed.application_url, None);
}

#[test]
fn reports_the_first_application_url_of_a_repeated_field() {
    // Both lines rewrite to the same listener, so the client cannot tell them apart; it uses the
    // first, and an appended duplicate must not steer the proxy somewhere else.
    let repl: SocketAddrV4 = "10.1.1.5:44747".parse().unwrap();
    let mut f = HttpFraming::new(Kind::Response, rewrite_all(repl));
    let framed = f
            .feed(
                b"HTTP/1.1 200 OK\r\nApplication-URL: http://10.0.0.7:8008/apps\r\nApplication-URL: http://10.0.0.9:9/x\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
    assert_eq!(
        framed.application_url,
        Some("10.0.0.7:8008".parse().unwrap())
    );
}

#[test]
fn a_trailing_location_does_not_displace_the_application_url() {
    let repl: SocketAddrV4 = "10.1.1.5:44747".parse().unwrap();
    let mut f = HttpFraming::new(Kind::Response, rewrite_all(repl));
    let framed = f
            .feed(
                b"HTTP/1.1 200 OK\r\nApplication-URL: http://10.0.0.7:8008/apps\r\nLocation: http://10.0.0.7:8008/apps/X/run\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
    assert_eq!(
        framed.application_url,
        Some("10.0.0.7:8008".parse().unwrap())
    );
}

#[test]
fn a_leading_location_does_not_hide_a_later_application_url() {
    let repl: SocketAddrV4 = "10.1.1.5:44747".parse().unwrap();
    let mut f = HttpFraming::new(Kind::Response, rewrite_all(repl));
    let framed = f
            .feed(
                b"HTTP/1.1 200 OK\r\nLocation: http://10.0.0.7:8008/apps/X/run\r\nApplication-URL: http://10.0.0.7:8008/apps\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
    assert_eq!(
        framed.application_url,
        Some("10.0.0.7:8008".parse().unwrap())
    );
}

#[test]
fn ignores_response_authority_headers_on_a_request() {
    // A client naming `Application-URL` would otherwise be reported to the owner, which learns it as
    // the device's REST base and dials it for every later REST client: a relay to any address the
    // target interface reaches. The request framer recognizes `Host` only, so both lines here are
    // neither reported nor rewritten, even under a policy that targets every header.
    let repl: SocketAddrV4 = "10.1.1.5:44747".parse().unwrap();
    let request = b"GET /dd.xml HTTP/1.1\r\n\
                         Application-URL: http://192.168.9.9:22/\r\n\
                         Location: http://192.168.9.9:23/\r\n\r\n";
    let mut f = HttpFraming::new(Kind::Request, rewrite_all(repl));
    let framed = f.feed(request).unwrap();
    assert_eq!(framed.application_url, None);
    assert_eq!(framed.header, request);
}

#[test]
fn ignores_a_host_header_on_a_response() {
    // The mirror of the request-side gate: the device can't steer the proxy's `Host` rewrite target.
    let repl: SocketAddrV4 = "10.1.1.5:44747".parse().unwrap();
    let mut f = HttpFraming::new(Kind::Response, rewrite_all(repl));
    let request = b"HTTP/1.1 200 OK\r\nHost: 192.168.9.9:22\r\nContent-Length: 0\r\n\r\n";
    let framed = f.feed(request).unwrap();
    assert_eq!(framed.application_url, None);
    assert_eq!(framed.header, request);
}

#[test]
fn rewrites_location_in_a_chunked_201() {
    let repl: SocketAddrV4 = "10.1.1.5:44747".parse().unwrap();
    let mut f = HttpFraming::new(Kind::Response, rewrite_all(repl));
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
    assert_eq!(f.phase, Phase::BodyChunked); // 201 is NOT special-cased; chunked frames it
}

#[test]
fn content_length_sets_the_body_phase() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nContent-Length: 1069\r\n\r\n")
        .unwrap();
    assert_eq!(f.phase, Phase::BodyContentLength);
    assert_eq!(f.body_remaining, 1069);
}

#[test]
fn a_bodyless_status_has_no_body_despite_a_content_length() {
    // 204 is bodyless regardless of headers (RFC 7230 §3.3.3 rule 1).
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    f.scan_and_rewrite_header(b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n")
        .unwrap();
    assert_eq!(f.phase, Phase::Header);
}

#[test]
fn a_response_without_framing_is_close_delimited() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n")
        .unwrap();
    assert_eq!(f.phase, Phase::BodyCloseDelimited);
}

#[test]
fn a_request_without_framing_is_bodyless() {
    let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
    f.scan_and_rewrite_header(b"GET / HTTP/1.1\r\n\r\n")
        .unwrap();
    assert_eq!(f.phase, Phase::Header);
}

#[test]
fn malformed_content_length_is_an_error() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    assert_eq!(
        f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nContent-Length: 12abc\r\n\r\n"),
        Err(FramingError::MalformedContentLength)
    );
}

#[test]
fn chunked_in_a_coding_list_is_detected() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
        .unwrap();
    assert_eq!(f.phase, Phase::BodyChunked);
}

/// Drive `f` over `input` like the proxy: feed, record `(header, body)`, consume, until an
/// incomplete header. Returns the framed messages as owned byte pairs.
fn drain(f: &mut HttpFraming, input: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut buf = input.to_vec();
    let mut out = Vec::new();
    loop {
        let framed = f.feed(&buf).unwrap();
        if framed.consumed == 0 {
            break;
        }
        let pair = (framed.header.to_vec(), framed.body.to_vec());
        let consumed = framed.consumed;
        out.push(pair);
        buf.drain(..consumed);
    }
    out
}

#[test]
fn frames_a_content_length_message() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    let msgs = drain(&mut f, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].0, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    assert_eq!(msgs[0].1, b"hello");
}

#[test]
fn frames_a_chunked_message_forwarding_the_body_opaquely() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    let msgs = drain(
        &mut f,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nbar\r\n0\r\n\r\n",
    );
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        msgs[0].0,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
    // The chunk framing rides out in the body untouched.
    assert_eq!(msgs[0].1, b"5\r\nhello\r\n3\r\nbar\r\n0\r\n\r\n");
}

#[test]
fn frames_multiple_keep_alive_messages() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    // A Content-Length response immediately followed by a chunked one on the same connection.
    let msgs = drain(
        &mut f,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi\
              HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nbye\r\n0\r\n\r\n",
    );
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].1, b"hi");
    assert_eq!(msgs[1].1, b"3\r\nbye\r\n0\r\n\r\n");
}

#[test]
fn forwards_chunked_trailers_opaquely() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    let msgs = drain(
        &mut f,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: v\r\n\r\n",
    );
    assert_eq!(msgs.len(), 1);
    // The trailer field and the closing blank line ride out in the body.
    assert_eq!(msgs[0].1, b"0\r\nX-Trailer: v\r\n\r\n");
}

#[test]
fn chunk_size_line_over_cap_is_refused() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    let mut input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    input.resize(input.len() + MAX_CHUNK_LINE + 1, b'f'); // a chunk-size line that never terminates
    assert!(matches!(
        f.feed(&input),
        Err(FramingError::ChunkLineTooLong)
    ));
}

#[test]
fn a_near_max_chunk_size_is_refused_not_overflowed() {
    // A hostile/buggy device sends the largest chunk size that fits `usize` on this target (its hex
    // width tracks the pointer width). It is under MAX_CHUNK_LINE so it passes the line-length guard;
    // adding the terminating CRLF would overflow, so the framer must refuse it cleanly rather than
    // panic (debug) or wrap (release).
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    let input = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
        usize::MAX
    );
    assert!(matches!(
        f.feed(input.as_bytes()),
        Err(FramingError::ChunkSizeTooLarge)
    ));
}

#[test]
fn trailer_line_over_cap_is_refused() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    let mut input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
    input.resize(input.len() + MAX_TRAILER_LINE + 1, b'a'); // a trailer line that never terminates
    assert!(matches!(
        f.feed(&input),
        Err(FramingError::TrailerLineTooLong)
    ));
}

#[test]
fn a_trailer_line_past_the_chunk_cap_is_tolerated() {
    // A trailer line longer than MAX_CHUNK_LINE but within MAX_TRAILER_LINE isn't refused, just
    // incomplete, awaiting its CRLF. A chunk-size line of the same length would be rejected.
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    let mut input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
    input.resize(input.len() + MAX_CHUNK_LINE + 1, b'a');
    assert!(f.feed(&input).is_ok());
}

#[test]
fn close_delimited_streams_the_body_across_feeds() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    let input = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nabc";
    let first = f.feed(input).unwrap();
    assert_eq!(first.header, b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n");
    assert_eq!(first.body, b"abc");
    assert_eq!(first.consumed, input.len()); // header + all arrived body
    // The phase stays close-delimited, so a later feed forwards more with no header.
    let second = f.feed(b"def").unwrap();
    assert_eq!(second.header, b"");
    assert_eq!(second.body, b"def");
}

#[test]
fn streams_a_content_length_body_across_feeds() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    // First feed: header + 3 of the 5 declared body bytes.
    let first = f
        .feed(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc")
        .unwrap();
    assert_eq!(
        first.header,
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    );
    assert_eq!(first.body, b"abc");
    // Second feed (after the owner consumed the first): the remaining 2 bytes, no header.
    let second = f.feed(b"de").unwrap();
    assert_eq!(second.header, b"");
    assert_eq!(second.body, b"de");
    assert_eq!(second.consumed, 2);
}

#[test]
fn an_incomplete_header_consumes_nothing() {
    let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
    let framed = f.feed(b"GET / HTTP/1.1\r\nHost: x").unwrap(); // no blank line yet
    assert_eq!(framed.consumed, 0);
    assert_eq!(framed.header, b"");
    assert_eq!(framed.body, b"");
}

#[test]
fn an_unterminated_oversize_header_errors() {
    let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
    let huge = vec![b'x'; MAX_HEADER + 1]; // no blank line, over the cap
    assert!(matches!(f.feed(&huge), Err(FramingError::HeaderTooLong)));
}

#[test]
fn a_malformed_chunk_size_errors() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    assert!(matches!(
        f.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n"),
        Err(FramingError::MalformedChunkSize)
    ));
}

#[test]
fn chunk_extensions_are_dropped_from_the_size() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    let msgs = drain(
        &mut f,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;name=value\r\nhello\r\n0\r\n\r\n",
    );
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].1, b"5;name=value\r\nhello\r\n0\r\n\r\n");
}

#[test]
fn rejects_a_content_length_beside_a_chunked_encoding() {
    // Both kinds in both orders: the check runs once the whole block is scanned, so neither
    // the side nor the header order should reach it.
    for (kind, block) in [
        (
            Kind::Response,
            &b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        ),
        (
            Kind::Response,
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 100\r\n\r\n"[..],
        ),
        (
            Kind::Request,
            &b"POST /apps/X HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        ),
        (
            Kind::Request,
            &b"POST /apps/X HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n"[..],
        ),
    ] {
        let mut f = HttpFraming::new(kind, RewritePolicy::NONE);
        assert_eq!(
            f.scan_and_rewrite_header(block),
            Err(FramingError::ContentLengthWithChunked)
        );
    }
}

#[test]
fn streams_a_chunked_body_across_feeds() {
    let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
    // First feed: header, the chunk-size line, and only part of the chunk data.
    let first = f
        .feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel")
        .unwrap();
    assert_eq!(
        first.header,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
    assert_eq!(first.body, b"5\r\nhel");
    // Second feed: the rest of the chunk (data + CRLF) then the terminating chunk.
    let second = f.feed(b"lo\r\n0\r\n\r\n").unwrap();
    assert_eq!(second.header, b"");
    assert_eq!(second.body, b"lo\r\n0\r\n\r\n");
}
