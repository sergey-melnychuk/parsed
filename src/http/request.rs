//! Requests.

use super::body::{BodyMatcher, request_framing};
use super::{
    BODY, Capture, Config, Copied, EncodeError, Framing, HEAD, Header, HeaderRef, Message,
    RawHeader, Spans, Version, ascii, ascii_ref, crlf, encode_headers, headers, is_tchar,
    is_visible, owned_headers, pairs, ref_headers, set_content_length, version,
};
use crate::matcher::{Boxed, MatchError, Matcher, ReadError, Resumable};
use crate::parser::{limit, repeat, tag};
use crate::stream::ByteStream;
use std::borrow::Cow;
use std::ops::Range;

/// An HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Method, e.g. `GET`.
    pub method: String,
    /// Request target, e.g. `/index.html?q=1`.
    pub target: String,
    /// Protocol version.
    pub version: Version,
    /// Header fields in the order received.
    pub headers: Vec<Header>,
    /// Body; for a chunked request, already decoded.
    pub body: Vec<u8>,
}

impl Request {
    /// HTTP/1.1 request without headers and body.
    pub fn new(method: impl Into<String>, target: impl Into<String>) -> Request {
        Request {
            method: method.into(),
            target: target.into(),
            version: Version::Http11,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push(Header::new(name, value));
        self
    }

    /// Set the body, replacing `Content-Length` and `Transfer-Encoding` headers with a
    /// matching `Content-Length`.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        set_content_length(&mut self.headers, self.body.len());
        self
    }

    /// Whether the client waits for `100 Continue` before sending the body.
    pub fn expects_continue(&self) -> bool {
        expects_continue(self)
    }

    /// Serialize the request, after validating method, target and headers (so that
    /// e.g. a header value with CRLF cannot inject headers). The body is written as is:
    /// headers must describe it (see [`Request::with_body`]).
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(64 + self.body.len());
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Like [`Request::encode`], appending to `out` (nothing is appended on error).
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let len = out.len();
        let result = self.write(out);
        if result.is_err() {
            out.truncate(len);
        }
        result
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.method.is_empty() || !self.method.bytes().all(is_tchar) {
            return Err(EncodeError("invalid method"));
        }
        if self.target.is_empty() || !self.target.bytes().all(is_visible) {
            return Err(EncodeError("invalid request target"));
        }
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.target.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.version.as_str().as_bytes());
        out.extend_from_slice(b"\r\n");
        encode_headers(&self.headers, out)?;
        out.extend_from_slice(&self.body);
        Ok(())
    }
}

impl Message for Request {
    fn version(&self) -> Version {
        self.version
    }

    fn header_pairs(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.headers
            .iter()
            .map(|h| (h.name.as_str(), h.value.as_slice()))
    }
}

/// An HTTP request borrowed from the parsed input, see [`parse_request_ref`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRef<'a> {
    /// Method, e.g. `GET`.
    pub method: &'a str,
    /// Request target, e.g. `/index.html?q=1`.
    pub target: &'a str,
    /// Protocol version.
    pub version: Version,
    /// Header fields in the order received.
    pub headers: Vec<HeaderRef<'a>>,
    /// Body: borrowed, except for a chunked body with more than one chunk.
    pub body: Cow<'a, [u8]>,
}

impl RequestRef<'_> {
    /// Whether the client waits for `100 Continue` before sending the body.
    pub fn expects_continue(&self) -> bool {
        expects_continue(self)
    }

    /// Copy into an owned [`Request`].
    pub fn into_owned(self) -> Request {
        Request {
            method: self.method.to_string(),
            target: self.target.to_string(),
            version: self.version,
            headers: self
                .headers
                .iter()
                .map(|h| Header::new(h.name, h.value))
                .collect(),
            body: self.body.into_owned(),
        }
    }
}

impl Message for RequestRef<'_> {
    fn version(&self) -> Version {
        self.version
    }

    fn header_pairs(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.headers.iter().map(|h| (h.name, h.value))
    }
}

fn expects_continue(m: &impl Message) -> bool {
    m.version() == Version::Http11 && m.has_token("Expect", "100-continue")
}

struct RawHead<F> {
    method: F,
    target: F,
    version: Version,
    headers: Vec<RawHeader<F>>,
}

fn head<C: Capture>(cfg: Config) -> impl Matcher<(RawHead<C::Field>, Framing)> {
    // empty lines before the request line are ignored (RFC 9112, section 2.2)
    let head = repeat(crlf())
        .then(C::field1(is_tchar, "method"))
        .then(tag(b" "))
        .then(C::field1(is_visible, "request target"))
        .then(tag(b" "))
        .then(version())
        .then(crlf())
        .then(headers::<C>(cfg.max_headers))
        .then(crlf())
        .map(
            |((((((((_, method), _), target), _), version), _), headers), _)| RawHead {
                method,
                target,
                version,
                headers,
            },
        );
    limit(cfg.max_head, head)
        .try_map_with(move |head, bs| {
            let framing = request_framing(
                head.version,
                pairs::<C>(&head.headers, bs),
                cfg.require_host,
            )?;
            Ok::<_, &'static str>((head, framing))
        })
        .context(HEAD)
}

fn message<C: Capture>(cfg: Config) -> impl Matcher<(RawHead<C::Field>, C::Body)> {
    head::<C>(cfg)
        .then_with(move |(_, framing)| BodyMatcher::<C>::new(*framing, &cfg).context(BODY))
        .map(|((head, _), body)| (head, body))
}

fn owned(head: RawHead<Vec<u8>>, body: Vec<u8>) -> Request {
    Request {
        method: ascii(head.method),
        target: ascii(head.target),
        version: head.version,
        headers: owned_headers(head.headers),
        body,
    }
}

/// Matcher for a whole request (see [`RequestParser`]).
pub fn request_matcher(cfg: Config) -> impl Matcher<Request> {
    message::<Copied>(cfg).map(|(head, body)| owned(head, body))
}

/// Matcher for a request head: the request without body, and how the body that follows
/// is framed (see [`RequestHeadParser`]).
pub fn request_head_matcher(cfg: Config) -> impl Matcher<(Request, Framing)> {
    head::<Copied>(cfg).map(|(head, framing)| (owned(head, Vec::new()), framing))
}

/// One-shot request parsing. On error the stream is left untouched; `Incomplete` means
/// the request is not fully buffered yet. See [`RequestParser`] to keep partial progress.
pub fn parse_request(bs: &mut ByteStream<'_>, cfg: &Config) -> Result<Request, MatchError> {
    request_matcher(*cfg).do_match(bs)
}

/// Zero-copy request parsing from a slice holding what has been received so far.
/// Returns the request borrowing from `buf`, and the number of bytes it takes;
/// `Incomplete` means more input is needed.
///
/// ```
/// use parsed::http::{Config, Message, parse_request_ref};
///
/// let buf = b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhiGET ...";
/// let (req, len) = parse_request_ref(buf, &Config::default()).unwrap();
/// assert_eq!(req.target, "/x");
/// assert_eq!(req.header_str("host"), Some("a"));
/// assert_eq!(&*req.body, b"hi");
/// assert_eq!(&buf[len..], b"GET ...");
/// ```
pub fn parse_request_ref<'a>(
    buf: &'a [u8],
    cfg: &Config,
) -> Result<(RequestRef<'a>, usize), MatchError> {
    let mut bs = ByteStream::partial(buf);
    let (head, body) = message::<Spans>(*cfg).do_match(&mut bs)?;
    let req = RequestRef {
        method: ascii_ref(&buf[head.method]),
        target: ascii_ref(&buf[head.target]),
        version: head.version,
        headers: ref_headers(&head.headers, buf),
        body: join(buf, body),
    };
    Ok((req, bs.offset()))
}

pub(crate) fn join<'a>(buf: &'a [u8], pieces: Vec<Range<usize>>) -> Cow<'a, [u8]> {
    match &pieces[..] {
        [] => Cow::Borrowed(&[]),
        [one] => Cow::Borrowed(&buf[one.clone()]),
        _ => Cow::Owned(pieces.into_iter().flat_map(|r| &buf[r]).copied().collect()),
    }
}

/// Resumable parser for whole requests: on `Incomplete` the progress is kept (and the
/// consumed bytes can be dropped with [`ByteStream::pull`]), and the next call continues
/// from there. Requests may be larger than the buffer, up to the [`Config`] limits.
///
/// ```
/// use parsed::http::RequestParser;
/// use parsed::stream::ByteStream;
///
/// let mut parser = RequestParser::default();
/// let mut bs = ByteStream::with_capacity(32);
///
/// bs.put(b"POST /upload HTTP/1.1\r\nHost: a\r\n");
/// assert!(parser.parse(&mut bs).unwrap_err().is_incomplete());
/// bs.pull();
/// bs.put(b"Content-Length: 5\r\n\r\nhello");
/// let req = parser.parse(&mut bs).unwrap();
/// assert_eq!(req.target, "/upload");
/// assert_eq!(req.body, b"hello");
/// ```
pub struct RequestParser(Resumable<Boxed<Request>, Request>);

impl RequestParser {
    /// Parser bounded by `cfg`.
    pub fn new(cfg: Config) -> Self {
        RequestParser(Resumable::new(request_matcher(cfg).boxed()))
    }

    /// Continue parsing the current request, see [`Resumable::parse`].
    pub fn parse(&mut self, bs: &mut ByteStream<'_>) -> Result<Request, MatchError> {
        self.0.parse(bs)
    }

    /// Parse the next request, reading from `reader` as needed; `None` at a clean end of
    /// input. See [`Resumable::read_from`].
    pub fn read_from<R: std::io::Read>(
        &mut self,
        bs: &mut ByteStream<'_>,
        reader: &mut R,
    ) -> Result<Option<Request>, ReadError> {
        self.0.read_from(bs, reader)
    }
}

impl Default for RequestParser {
    fn default() -> Self {
        RequestParser::new(Config::default())
    }
}

/// Resumable parser for request heads, for streaming bodies: produces the request
/// without body, and the [`Framing`] of the body, to decode with a
/// [`BodyDecoder`](super::BodyDecoder).
pub struct RequestHeadParser(Resumable<Boxed<(Request, Framing)>, (Request, Framing)>);

impl RequestHeadParser {
    /// Parser bounded by `cfg`.
    pub fn new(cfg: Config) -> Self {
        RequestHeadParser(Resumable::new(request_head_matcher(cfg).boxed()))
    }

    /// Continue parsing the current request head, see [`Resumable::parse`].
    pub fn parse(&mut self, bs: &mut ByteStream<'_>) -> Result<(Request, Framing), MatchError> {
        self.0.parse(bs)
    }

    /// Parse the next request head and body framing, reading from `reader` as needed; `None` at a clean end of
    /// input. See [`Resumable::read_from`].
    pub fn read_from<R: std::io::Read>(
        &mut self,
        bs: &mut ByteStream<'_>,
        reader: &mut R,
    ) -> Result<Option<(Request, Framing)>, ReadError> {
        self.0.read_from(bs, reader)
    }
}

impl Default for RequestHeadParser {
    fn default() -> Self {
        RequestHeadParser::new(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{BodyDecoder, error_status};
    use crate::testing::feed;

    const UPGRADE: &str =
        "GET /chat HTTP/1.1\r\nHost: example.com:8000\r\nUpgrade: websocket\r\n\r\n";

    fn parse(text: &str) -> (Result<Request, MatchError>, ByteStream<'static>) {
        let mut bs: ByteStream = text.to_string().into();
        let r = parse_request(&mut bs, &Config::default());
        (r, bs)
    }

    fn fed(text: &[u8], chunk: usize) -> Result<Request, MatchError> {
        feed(request_matcher(Config::default()), text, chunk, false)
    }

    #[test]
    fn curl_request() {
        let text = "GET / HTTP/1.1\r\nHost: localhost:9000\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\n\r\n";
        let req = parse(text).0.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.target, "/");
        assert_eq!(req.version, Version::Http11);
        let headers: Vec<_> = req.header_pairs().collect();
        assert_eq!(
            headers,
            vec![
                ("Host", &b"localhost:9000"[..]),
                ("User-Agent", b"curl/7.64.1"),
                ("Accept", b"*/*"),
            ]
        );
        assert!(req.body.is_empty());
        assert!(req.keep_alive());
    }

    #[test]
    fn request_with_body() {
        let text = "POST /docs/index.html HTTP/1.1\r\nHost: www.nowhere123.com\r\nAccept: image/gif, image/jpeg, */*\r\nContent-Length: 8\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n\r\n0123456\n";
        let req = parse(text).0.unwrap();
        assert_eq!(req.body, b"0123456\n");
        assert_eq!(req.header_str("accept"), Some("image/gif, image/jpeg, */*"));
        assert_eq!(
            req.header_str("User-Agent"),
            Some("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)")
        );
    }

    #[test]
    fn partial_request_is_incomplete_and_not_consumed() {
        let text = "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello";
        for cut in 0..text.len() {
            let (r, bs) = parse(&text[..cut]);
            let e = r.unwrap_err();
            assert!(e.is_incomplete(), "cut={}: {}", cut, e);
            assert_eq!(bs.pos(), 0, "cut={}", cut);
            let e = parse_request_ref(&text.as_bytes()[..cut], &Config::default()).unwrap_err();
            assert!(e.is_incomplete(), "ref cut={}: {}", cut, e);
        }
        let (r, bs) = parse(text);
        assert_eq!(r.unwrap().body, b"hello");
        assert_eq!(bs.remaining(), 0);
    }

    #[test]
    fn pipelined_requests_and_leading_empty_lines() {
        let text = format!("{}\r\n\r\n{}", UPGRADE, UPGRADE);
        let mut bs: ByteStream = text.into();
        let cfg = Config::default();
        assert_eq!(parse_request(&mut bs, &cfg).unwrap().target, "/chat");
        assert_eq!(parse_request(&mut bs, &cfg).unwrap().target, "/chat");
        assert!(parse_request(&mut bs, &cfg).unwrap_err().is_incomplete());
    }

    #[test]
    fn malformed_requests_are_rejected() {
        for text in &[
            "GET /\r\nHost: a b\r\n\r\n",
            " / HTTP/1.1\r\nHost: a\r\n\r\n",
            "G(T / HTTP/1.1\r\nHost: a\r\n\r\n",
            "GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
            "GET / HTTP/2.0\r\nHost: a\r\n\r\n",
            "GET / HTTP/1.2\r\nHost: a\r\n\r\n",
            "GET / HTTP/1.10\r\nHost: a\r\n\r\n",
            "GET / http/1.1\r\nHost: a\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nBad Name: x\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nName : x\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nNoColon\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nA: b\nC: d\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nA: b\x00c\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nA: b\rc\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nA: b\r\n folded\r\n\r\n",
            "GET / HTTP/1.1\n\n",
            "GET / HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: abc\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx",
            "GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n",
            "GET / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nx\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nab\r\n0\r\n\r\n",
        ] {
            let (r, bs) = parse(text);
            let e = r.expect_err(text);
            assert!(!e.is_incomplete(), "{:?}: {}", text, e);
            assert_eq!(error_status(&e), Some(400), "{:?}: {}", text, e);
            assert_eq!(bs.pos(), 0, "{:?}", text);
            let e = fed(text.as_bytes(), 3).expect_err(text);
            assert!(!e.is_incomplete(), "{:?}: {}", text, e);
            let e = parse_request_ref(text.as_bytes(), &Config::default()).expect_err(text);
            assert!(!e.is_incomplete(), "{:?}: {}", text, e);
        }
    }

    #[test]
    fn header_whitespace_and_case() {
        let text = b"GET / HTTP/1.1\r\nHost: h\r\nA:b\r\nB: \t c  \r\nC:\r\ncontent-length: 2\r\nD: \xff\r\n\r\nok";
        let mut bs = ByteStream::borrow(text);
        let req = parse_request(&mut bs, &Config::default()).unwrap();
        assert_eq!(req.header_str("a"), Some("b"));
        assert_eq!(req.header_str("B"), Some("c"));
        assert_eq!(req.header_str("C"), Some(""));
        assert_eq!(req.header("D"), Some(&b"\xff"[..]));
        assert_eq!(req.header_str("D"), None);
        assert_eq!(req.header("missing"), None);
        assert_eq!(req.body, b"ok");
    }

    #[test]
    fn keep_alive_and_expect() {
        let req = |v: &str, h: &str| {
            parse(&format!("GET / HTTP/1.{}\r\nHost: a\r\n{}\r\n", v, h))
                .0
                .unwrap()
        };
        assert!(req("1", "").keep_alive());
        assert!(!req("1", "Connection: Close\r\n").keep_alive());
        assert!(!req("1", "Connection: upgrade, close\r\n").keep_alive());
        assert!(!req("0", "").keep_alive());
        assert!(req("0", "Connection: keep-alive\r\n").keep_alive());
        assert!(req("1", "Expect: 100-Continue\r\n").expects_continue());
        assert!(!req("0", "Expect: 100-continue\r\n").expects_continue());
    }

    #[test]
    fn limits() {
        let too_many = format!(
            "GET / HTTP/1.1\r\nHost: a\r\n{}\r\n",
            "A: b\r\n".repeat(100)
        );
        let e = parse(&too_many).0.unwrap_err();
        assert!(e.to_string().ends_with("too many headers"), "{}", e);

        let too_long = format!(
            "GET / HTTP/1.1\r\nHost: a\r\nA: {}\r\n\r\n",
            "x".repeat(16 << 10)
        );
        for e in [
            parse(&too_long).0.unwrap_err(),
            fed(too_long.as_bytes(), 100).unwrap_err(),
            parse_request_ref(too_long.as_bytes(), &Config::default()).unwrap_err(),
        ] {
            assert_eq!(error_status(&e), Some(431), "{}", e);
            assert_eq!(
                e.to_string(),
                "at offset 0: head: limit of 16384 bytes exceeded"
            );
        }

        let too_big = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1048577\r\n\r\n";
        let e = parse(too_big).0.unwrap_err();
        assert_eq!(error_status(&e), Some(413), "{}", e);

        let cfg = Config {
            max_body: 10,
            ..Config::default()
        };
        let chunked = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
            5\r\nhello\r\n5\r\nhello\r\n5\r\nhello\r\n0\r\n\r\n";
        let e = parse_request(&mut ByteStream::borrow(chunked.as_bytes()), &cfg).unwrap_err();
        assert_eq!(error_status(&e), Some(413), "{}", e);
        let trailers = format!(
            "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nT: {}\r\n\r\n",
            "x".repeat(16 << 10)
        );
        assert!(
            parse(&trailers)
                .0
                .unwrap_err()
                .to_string()
                .contains("limit of 16384 bytes")
        );
    }

    #[test]
    fn chunked_request() {
        let text = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n\
            5\r\nhello\r\n7;ext=1\r\n, world\r\n000\r\nTrailer: x\r\n\r\nNEXT";
        let (r, bs) = parse(text);
        assert_eq!(r.unwrap().body, b"hello, world");
        assert_eq!(bs.as_ref(), b"NEXT");
        for chunk in 1..10 {
            assert_eq!(fed(text.as_bytes(), chunk).unwrap().body, b"hello, world");
        }
        let (req, len) = parse_request_ref(text.as_bytes(), &Config::default()).unwrap();
        assert_eq!(&*req.body, b"hello, world");
        assert!(matches!(req.body, Cow::Owned(_)));
        assert_eq!(&text[len..], "NEXT");
    }

    #[test]
    fn zero_copy_request() {
        let text = b"PUT /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
        let (req, len) = parse_request_ref(text, &Config::default()).unwrap();
        assert_eq!(len, text.len());
        assert_eq!(req.method.as_ptr(), text.as_ptr());
        assert_eq!(req.headers[0].value.as_ptr(), text[23..].as_ptr());
        assert!(matches!(req.body, Cow::Borrowed(b"abc")));
        assert_eq!(
            req.clone().into_owned(),
            parse(std::str::from_utf8(text).unwrap()).0.unwrap()
        );
    }

    #[test]
    fn request_parser_across_chunks() {
        let body = "x".repeat(1000);
        let text = format!(
            "POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\n\r\n{}{}",
            body, UPGRADE
        );
        let mut parser = RequestParser::default();
        let mut bs = ByteStream::with_capacity(80);
        let mut requests = vec![];
        for chunk in text.as_bytes().chunks(64) {
            bs.pull();
            assert_eq!(bs.put(chunk), chunk.len());
            loop {
                match parser.parse(&mut bs) {
                    Ok(r) => requests.push(r),
                    Err(e) if e.is_incomplete() => break,
                    Err(e) => panic!("{}", e),
                }
            }
        }
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body, body.as_bytes());
        assert_eq!(requests[1].target, "/chat");
    }

    #[test]
    fn streaming_head_then_body() {
        let text = b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
            4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n";
        let mut heads = RequestHeadParser::default();
        let mut bs = ByteStream::with_capacity(32);
        let mut rest = &text[..];
        let mut head = None;
        let mut body = Vec::new();
        let mut decoder: Option<BodyDecoder> = None;
        while !decoder.as_ref().is_some_and(|d| d.is_done()) {
            bs.pull();
            let n = bs.cap().min(rest.len()).min(8);
            bs.put(&rest[..n]);
            rest = &rest[n..];
            if head.is_none() {
                match heads.parse(&mut bs) {
                    Ok((req, framing)) => {
                        assert_eq!(framing, Framing::Chunked);
                        decoder = Some(BodyDecoder::new(framing, &Config::default()));
                        head = Some(req);
                    }
                    Err(e) if e.is_incomplete() => continue,
                    Err(e) => panic!("{}", e),
                }
            }
            let decoder = decoder.as_mut().unwrap();
            loop {
                match decoder.decode(&mut bs) {
                    Ok(Some(piece)) => body.extend_from_slice(piece),
                    Ok(None) => break,
                    Err(e) if e.is_incomplete() => break,
                    Err(e) => panic!("{}", e),
                }
            }
        }
        assert_eq!(head.unwrap().target, "/up");
        assert_eq!(body, b"abcdefgh");
    }

    #[test]
    fn encoding() {
        let req = Request::new("POST", "/x")
            .with_header("Host", "a")
            .with_header("Content-Length", "99")
            .with_body("hi");
        let wire = req.encode().unwrap();
        assert_eq!(
            wire,
            b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi"
        );
        let mut bs = ByteStream::borrow(&wire);
        assert_eq!(parse_request(&mut bs, &Config::default()).unwrap(), req);

        for bad in [
            Request::new("GET /", "/"),
            Request::new("GET", "/a b"),
            Request::new("GET", ""),
            Request::new("GET", "/").with_header("X", "a\r\nInjected: 1"),
            Request::new("GET", "/").with_header("Bad Name", "x"),
        ] {
            let mut out = b"keep".to_vec();
            assert!(bad.encode_into(&mut out).is_err(), "{:?}", bad);
            assert_eq!(out, b"keep");
        }
    }

    #[test]
    fn chunk_invariance() {
        fn f(prefix: u8, data: Vec<u8>, chunk: u8) -> bool {
            let mut input = match prefix % 4 {
                0 => vec![],
                1 => b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec(),
                2 => b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n".to_vec(),
                _ => b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
            };
            let alphabet = b"\r\n: ;0123aAfF\t,";
            input.extend(data.iter().map(|b| {
                if b % 2 == 0 {
                    alphabet[(*b as usize / 2) % alphabet.len()]
                } else {
                    *b
                }
            }));
            let cfg = Config::default();
            let mut bs = ByteStream::wrap(input.clone());
            let whole = parse_request(&mut bs, &cfg);
            if whole.is_err() && bs.pos() != 0 {
                return false;
            }
            let fed = feed(request_matcher(cfg), &input, chunk as usize, true);
            let zero_copy = parse_request_ref(&input, &cfg).map(|(r, _)| r.into_owned());
            match (&whole, &fed) {
                (Ok(a), Ok(b)) => a == b && zero_copy.as_ref() == Ok(a),
                (Err(a), Err(b)) => a.kind() == b.kind(),
                _ => false,
            }
        }
        quickcheck::QuickCheck::new()
            .tests(10_000)
            .quickcheck(f as fn(u8, Vec<u8>, u8) -> bool);
    }
}
