//! Responses.

use super::body::{BodyMatcher, response_framing};
use super::request::join;
use super::{
    BODY, Capture, Config, Copied, EncodeError, Framing, HEAD, Header, HeaderRef, Message,
    RawHeader, Spans, Version, crlf, encode_headers, headers, is_field_byte, owned_headers, pairs,
    ref_headers, set_content_length, trim_ows, version,
};
use crate::matcher::{Boxed, MatchError, Matcher, ReadError, Resumable};
use crate::parser::{limit, tag};
use crate::stream::ByteStream;
use std::borrow::Cow;

/// An HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Protocol version.
    pub version: Version,
    /// Status code, e.g. 200.
    pub status: u16,
    /// Reason phrase, e.g. `OK` (bytes that are not valid UTF-8 are replaced with U+FFFD).
    pub reason: String,
    /// Header fields in the order received.
    pub headers: Vec<Header>,
    /// Body; for a chunked response, already decoded.
    pub body: Vec<u8>,
}

impl Response {
    /// HTTP/1.1 response without headers and body.
    pub fn new(status: u16, reason: impl Into<String>) -> Response {
        Response {
            version: Version::Http11,
            status,
            reason: reason.into(),
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

    /// Whether this is an interim (1xx) response, to be followed by another response
    /// to the same request.
    pub fn is_informational(&self) -> bool {
        (100..200).contains(&self.status)
    }

    /// Serialize the response, after validating the status line and headers (so that
    /// e.g. a header value with CRLF cannot inject headers). The body is written as is:
    /// headers must describe it (see [`Response::with_body`]).
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(64 + self.body.len());
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Like [`Response::encode`], appending to `out` (nothing is appended on error).
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let len = out.len();
        let result = self.write(out);
        if result.is_err() {
            out.truncate(len);
        }
        result
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if !(100..=999).contains(&self.status) {
            return Err(EncodeError("invalid status code"));
        }
        if !self.reason.bytes().all(is_field_byte) {
            return Err(EncodeError("invalid reason phrase"));
        }
        out.extend_from_slice(self.version.as_str().as_bytes());
        out.extend_from_slice(format!(" {} ", self.status).as_bytes());
        out.extend_from_slice(self.reason.as_bytes());
        out.extend_from_slice(b"\r\n");
        encode_headers(&self.headers, out)?;
        out.extend_from_slice(&self.body);
        Ok(())
    }
}

impl Message for Response {
    fn version(&self) -> Version {
        self.version
    }

    fn header_pairs(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.headers
            .iter()
            .map(|h| (h.name.as_str(), h.value.as_slice()))
    }
}

/// An HTTP response borrowed from the parsed input, see [`parse_response_ref`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseRef<'a> {
    /// Protocol version.
    pub version: Version,
    /// Status code, e.g. 200.
    pub status: u16,
    /// Reason phrase (borrowed if valid UTF-8).
    pub reason: Cow<'a, str>,
    /// Header fields in the order received.
    pub headers: Vec<HeaderRef<'a>>,
    /// Body: borrowed, except for a chunked body with more than one chunk.
    pub body: Cow<'a, [u8]>,
}

impl ResponseRef<'_> {
    /// Copy into an owned [`Response`].
    pub fn into_owned(self) -> Response {
        Response {
            version: self.version,
            status: self.status,
            reason: self.reason.into_owned(),
            headers: self
                .headers
                .iter()
                .map(|h| Header::new(h.name, h.value))
                .collect(),
            body: self.body.into_owned(),
        }
    }
}

impl Message for ResponseRef<'_> {
    fn version(&self) -> Version {
        self.version
    }

    fn header_pairs(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.headers.iter().map(|h| (h.name, h.value))
    }
}

struct RawHead<F> {
    version: Version,
    status: u16,
    reason: F,
    headers: Vec<RawHeader<F>>,
}

fn status_code(bs: &mut ByteStream<'_>) -> Result<u16, MatchError> {
    let digits = bs.as_ref();
    if let Some(i) = digits.iter().take(3).position(|b| !b.is_ascii_digit()) {
        return Err(MatchError::unexpected(
            bs.offset() + i,
            Some(digits[i]),
            "3-digit status code",
        ));
    }
    if digits.len() < 3 {
        return Err(MatchError::incomplete(bs.offset(), 3, digits.len()));
    }
    let code = digits[..3]
        .iter()
        .fold(0u16, |acc, b| acc * 10 + (b - b'0') as u16);
    if code < 100 {
        return Err(MatchError::invalid(bs.offset(), "invalid status code"));
    }
    bs.skip(3);
    Ok(code)
}

// Request method the response answers: it affects how the body is framed.
#[derive(Clone, Copy)]
struct Method {
    bytes: [u8; 8],
}

impl Method {
    fn new(method: &str) -> Method {
        // only HEAD and CONNECT matter
        let mut bytes = [0u8; 8];
        if method.len() <= 8 {
            bytes[..method.len()].copy_from_slice(method.as_bytes());
        }
        Method { bytes }
    }

    fn as_bytes(&self) -> &[u8] {
        let len = self.bytes.iter().position(|b| *b == 0).unwrap_or(8);
        &self.bytes[..len]
    }
}

fn head<C: Capture>(cfg: Config, method: Method) -> impl Matcher<(RawHead<C::Field>, Framing)> {
    let head = version()
        .then(tag(b" "))
        .then(status_code)
        // the space before an empty reason phrase is often omitted
        .then(|bs: &mut ByteStream<'_>| match bs.peek() {
            Some(b' ') => {
                bs.next();
                Ok(())
            }
            Some(b'\r') => Ok(()),
            found @ Some(_) => Err(MatchError::unexpected(bs.offset(), found, "' ' or CRLF")),
            None => Err(MatchError::incomplete(bs.offset(), 1, 0)),
        })
        .then(C::field(is_field_byte))
        .then(crlf())
        .then(headers::<C>(cfg.max_headers))
        .then(crlf())
        .map(
            |(((((((version, _), status), _), reason), _), headers), _)| RawHead {
                version,
                status,
                reason,
                headers,
            },
        );
    limit(cfg.max_head, head)
        .try_map_with(move |head, bs| {
            let framing = response_framing(
                method.as_bytes(),
                head.status,
                pairs::<C>(&head.headers, bs),
            )?;
            Ok::<_, &'static str>((head, framing))
        })
        .context(HEAD)
}

fn message<C: Capture>(cfg: Config, method: Method) -> impl Matcher<(RawHead<C::Field>, C::Body)> {
    head::<C>(cfg, method)
        .then_with(move |(_, framing)| BodyMatcher::<C>::new(*framing, &cfg).context(BODY))
        .map(|((head, _), body)| (head, body))
}

fn owned(head: RawHead<Vec<u8>>, body: Vec<u8>) -> Response {
    Response {
        version: head.version,
        status: head.status,
        reason: String::from_utf8_lossy(trim_ows(&head.reason)).into_owned(),
        headers: owned_headers(head.headers),
        body,
    }
}

/// Matcher for a whole response to a request with the given method (see
/// [`ResponseParser`]).
pub fn response_matcher(cfg: Config, request_method: &str) -> impl Matcher<Response> + use<> {
    message::<Copied>(cfg, Method::new(request_method)).map(|(head, body)| owned(head, body))
}

/// Matcher for a response head: the response without body, and how the body that
/// follows is framed (see [`ResponseHeadParser`]).
pub fn response_head_matcher(
    cfg: Config,
    request_method: &str,
) -> impl Matcher<(Response, Framing)> + use<> {
    head::<Copied>(cfg, Method::new(request_method))
        .map(|(head, framing)| (owned(head, Vec::new()), framing))
}

/// One-shot parsing of a response to a request with the given method. On error the
/// stream is left untouched; `Incomplete` means the response is not fully buffered yet
/// (a body delimited by closing the connection ends when the stream is closed).
pub fn parse_response(
    bs: &mut ByteStream<'_>,
    request_method: &str,
    cfg: &Config,
) -> Result<Response, MatchError> {
    response_matcher(*cfg, request_method).do_match(bs)
}

/// Zero-copy parsing of a response to a request with the given method, from a slice
/// holding what has been received so far (`eof`: whether the connection is closed, which
/// ends a body delimited by closing the connection). Returns the response borrowing
/// from `buf`, and the number of bytes it takes; `Incomplete` means more input is needed.
///
/// ```
/// use parsed::http::{Config, parse_response_ref};
///
/// let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
/// let (res, len) = parse_response_ref(buf, "GET", false, &Config::default()).unwrap();
/// assert_eq!((res.status, &*res.reason, &*res.body), (200, "OK", &b"hi"[..]));
/// assert_eq!(len, buf.len());
/// ```
pub fn parse_response_ref<'a>(
    buf: &'a [u8],
    request_method: &str,
    eof: bool,
    cfg: &Config,
) -> Result<(ResponseRef<'a>, usize), MatchError> {
    let mut bs = if eof {
        ByteStream::borrow(buf)
    } else {
        ByteStream::partial(buf)
    };
    let (head, body) = message::<Spans>(*cfg, Method::new(request_method)).do_match(&mut bs)?;
    let res = ResponseRef {
        version: head.version,
        status: head.status,
        reason: String::from_utf8_lossy(trim_ows(&buf[head.reason])),
        headers: ref_headers(&head.headers, buf),
        body: join(buf, body),
    };
    Ok((res, bs.offset()))
}

/// Resumable parser for whole responses, see
/// [`RequestParser`](super::RequestParser). The request method is needed because
/// responses to `HEAD` and `CONNECT` requests have no body.
pub struct ResponseParser(Resumable<Boxed<Response>, Response>);

impl ResponseParser {
    /// Parser for responses to requests with the given method, bounded by `cfg`.
    pub fn new(cfg: Config, request_method: &str) -> Self {
        ResponseParser(Resumable::new(
            response_matcher(cfg, request_method).boxed(),
        ))
    }

    /// Continue parsing the current response, see [`Resumable::parse`].
    pub fn parse(&mut self, bs: &mut ByteStream<'_>) -> Result<Response, MatchError> {
        self.0.parse(bs)
    }

    /// Parse the next response, reading from `reader` as needed; `None` at a clean end of
    /// input. See [`Resumable::read_from`].
    pub fn read_from<R: std::io::Read>(
        &mut self,
        bs: &mut ByteStream<'_>,
        reader: &mut R,
    ) -> Result<Option<Response>, ReadError> {
        self.0.read_from(bs, reader)
    }
}

/// Resumable parser for response heads, for streaming bodies, see
/// [`RequestHeadParser`](super::RequestHeadParser).
pub struct ResponseHeadParser(Resumable<Boxed<(Response, Framing)>, (Response, Framing)>);

impl ResponseHeadParser {
    /// Parser for responses to requests with the given method, bounded by `cfg`.
    pub fn new(cfg: Config, request_method: &str) -> Self {
        ResponseHeadParser(Resumable::new(
            response_head_matcher(cfg, request_method).boxed(),
        ))
    }

    /// Continue parsing the current response head, see [`Resumable::parse`].
    pub fn parse(&mut self, bs: &mut ByteStream<'_>) -> Result<(Response, Framing), MatchError> {
        self.0.parse(bs)
    }

    /// Parse the next response head and body framing, reading from `reader` as needed; `None` at a clean end of
    /// input. See [`Resumable::read_from`].
    pub fn read_from<R: std::io::Read>(
        &mut self,
        bs: &mut ByteStream<'_>,
        reader: &mut R,
    ) -> Result<Option<(Response, Framing)>, ReadError> {
        self.0.read_from(bs, reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::feed;

    fn parse(text: &[u8], method: &str) -> Result<Response, MatchError> {
        parse_response(&mut ByteStream::borrow(text), method, &Config::default())
    }

    #[test]
    fn content_length_response() {
        let text =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhelloNEXT";
        let mut bs = ByteStream::borrow(text);
        let res = parse_response(&mut bs, "GET", &Config::default()).unwrap();
        assert_eq!(
            (res.version, res.status, res.reason.as_str()),
            (Version::Http11, 200, "OK")
        );
        assert_eq!(res.header_str("content-type"), Some("text/plain"));
        assert_eq!(res.body, b"hello");
        assert_eq!(bs.as_ref(), b"NEXT");
        assert!(res.keep_alive());
    }

    #[test]
    fn body_rules() {
        let with_body = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(parse(with_body, "HEAD").unwrap().body, b"");
        for status in [
            "100 Continue",
            "101 Switching Protocols",
            "204 No Content",
            "304 Not Modified",
        ] {
            let text = format!("HTTP/1.1 {}\r\nContent-Length: 5\r\n\r\n", status);
            assert_eq!(
                parse(text.as_bytes(), "GET").unwrap().body,
                b"",
                "{}",
                status
            );
        }
        let interim = parse(b"HTTP/1.1 100 Continue\r\n\r\n", "POST").unwrap();
        assert!(interim.is_informational());

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        assert_eq!(parse(chunked, "GET").unwrap().body, b"abc");

        // body until the connection closes
        let until_close = b"HTTP/1.0 200 OK\r\n\r\nall of it";
        assert_eq!(parse(until_close, "GET").unwrap().body, b"all of it");
        let mut open = ByteStream::partial(until_close);
        let e = parse_response(&mut open, "GET", &Config::default()).unwrap_err();
        assert!(e.is_incomplete());
        let (res, _) = parse_response_ref(until_close, "GET", true, &Config::default()).unwrap();
        assert_eq!(&*res.body, b"all of it");
        assert!(
            parse_response_ref(until_close, "GET", false, &Config::default())
                .unwrap_err()
                .is_incomplete()
        );

        let tunnel = b"HTTP/1.1 200 Connection Established\r\n\r\nTLS...";
        let (res, len) = parse_response_ref(tunnel, "CONNECT", false, &Config::default()).unwrap();
        assert_eq!((res.status, &tunnel[len..]), (200, &b"TLS..."[..]));
    }

    #[test]
    fn status_line_variants() {
        let res = parse(b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n", "GET").unwrap();
        assert_eq!((res.status, res.reason.as_str()), (200, ""));
        let res = parse(b"HTTP/1.1 404 \r\nContent-Length: 0\r\n\r\n", "GET").unwrap();
        assert_eq!(res.reason, "");
        let res = parse(
            b"HTTP/1.1 500 Internal \xffError\r\nContent-Length: 0\r\n\r\n",
            "GET",
        )
        .unwrap();
        assert_eq!(res.reason, "Internal \u{fffd}Error");
        for bad in [
            &b"HTTP/1.1 20 OK\r\n\r\n"[..],
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 099 Weird\r\n\r\n",
            b"HTTP/1.1  200 OK\r\n\r\n",
            b"HTTP/2 200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
            b"HTTP/1.1 200 O\x00K\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            let e = parse(bad, "GET").unwrap_err();
            assert!(
                !e.is_incomplete(),
                "{:?}: {}",
                String::from_utf8_lossy(bad),
                e
            );
        }
    }

    #[test]
    fn resumable_and_zero_copy_agree() {
        let text = b"HTTP/1.1 201 Created\r\nLocation: /x\r\nTransfer-Encoding: chunked\r\n\r\n\
            2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n";
        let one_shot = parse(text, "POST").unwrap();
        for chunk in 1..16 {
            let fed = feed(
                response_matcher(Config::default(), "POST"),
                text,
                chunk,
                false,
            );
            assert_eq!(fed.unwrap(), one_shot);
        }
        let (res, len) = parse_response_ref(text, "POST", false, &Config::default()).unwrap();
        assert_eq!(len, text.len());
        assert_eq!(res.into_owned(), one_shot);

        let mut parser = ResponseParser::new(Config::default(), "POST");
        let mut bs = ByteStream::with_capacity(32);
        let mut parsed = None;
        for piece in text.chunks(16) {
            bs.pull();
            bs.put(piece);
            match parser.parse(&mut bs) {
                Ok(r) => parsed = Some(r),
                Err(e) => assert!(e.is_incomplete(), "{}", e),
            }
        }
        assert_eq!(parsed.unwrap(), one_shot);
    }

    #[test]
    fn head_parser_reports_framing() {
        let mut heads = ResponseHeadParser::new(Config::default(), "GET");
        let mut bs = ByteStream::borrow(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123");
        let (res, framing) = heads.parse(&mut bs).unwrap();
        assert_eq!((res.status, framing), (200, Framing::Length(10)));
        assert_eq!(bs.as_ref(), b"0123");
    }

    #[test]
    fn encoding() {
        let res = Response::new(200, "OK")
            .with_header("Content-Type", "text/plain")
            .with_body("hello");
        let wire = res.encode().unwrap();
        assert_eq!(
            wire,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
        );
        assert_eq!(parse(&wire, "GET").unwrap(), res);

        let empty = Response::new(204, "No Content").encode().unwrap();
        assert_eq!(empty, b"HTTP/1.1 204 No Content\r\n\r\n");

        let binary = Response::new(200, "OK").with_body(vec![0u8, 0xFF, 0xC3, 0x28]);
        assert!(binary.encode().unwrap().ends_with(&[0, 0xFF, 0xC3, 0x28]));

        for bad in [
            Response::new(99, "x"),
            Response::new(1000, "x"),
            Response::new(200, "O\r\nK"),
            Response::new(200, "OK").with_header("Set-Cookie", "a\r\n\r\n<html>"),
        ] {
            assert!(bad.encode().is_err(), "{:?}", bad);
        }
    }

    #[test]
    fn chunk_invariance() {
        fn f(prefix: u8, data: Vec<u8>, chunk: u8, method: bool) -> bool {
            let mut input = match prefix % 4 {
                0 => vec![],
                1 => b"HTTP/1.1 200 OK\r\n".to_vec(),
                2 => b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n".to_vec(),
                _ => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
            };
            let alphabet = b"\r\n: ;0123aAfF\t,";
            input.extend(data.iter().map(|b| {
                if b % 2 == 0 {
                    alphabet[(*b as usize / 2) % alphabet.len()]
                } else {
                    *b
                }
            }));
            let method = if method { "GET" } else { "HEAD" };
            let cfg = Config::default();
            let mut bs = ByteStream::wrap(input.clone());
            let whole = parse_response(&mut bs, method, &cfg);
            if whole.is_err() && bs.pos() != 0 {
                return false;
            }
            let fed = feed(response_matcher(cfg, method), &input, chunk as usize, true);
            let zero_copy =
                parse_response_ref(&input, method, true, &cfg).map(|(r, _)| r.into_owned());
            match (&whole, &fed) {
                (Ok(a), Ok(b)) => a == b && zero_copy.as_ref() == Ok(a),
                (Err(a), Err(b)) => a.kind() == b.kind(),
                _ => false,
            }
        }
        quickcheck::QuickCheck::new()
            .tests(10_000)
            .quickcheck(f as fn(u8, Vec<u8>, u8, bool) -> bool);
    }
}
