//! HTTP/1.x messages ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)).
//!
//! Parsing comes in three shapes, for both requests and responses:
//!
//! - **whole message, owned**: [`RequestParser`] / [`ResponseParser`] (resumable: the
//!   message may be larger than the buffer), [`parse_request`] / [`parse_response`]
//!   (one-shot);
//! - **whole message, zero-copy**: [`parse_request_ref`] / [`parse_response_ref`] borrow
//!   from the input slice (a chunked body is the only thing that has to be copied);
//! - **streaming**: [`RequestHeadParser`] / [`ResponseHeadParser`] parse the head, then a
//!   [`BodyDecoder`] yields the body in pieces borrowed from the buffer, so bodies of any
//!   size can be processed in constant memory.
//!
//! Parsing is strict, to be safe against request smuggling and similar attacks:
//! token and field value characters are validated, obsolete line folding and bare LF are
//! rejected, only HTTP/1.0 and HTTP/1.1 are accepted, and ambiguous body framing
//! (`Transfer-Encoding` together with `Content-Length`, conflicting `Content-Length`
//! values, unknown transfer codings in requests) is rejected. Sizes are bounded by
//! [`Config`]. See [`error_status`] for the status code to answer a rejected request with.

mod body;
mod request;
mod response;

pub use body::{BodyDecoder, Framing, encode_chunk, encode_last_chunk};
pub use request::{
    Request, RequestHeadParser, RequestParser, RequestRef, parse_request, parse_request_ref,
    request_head_matcher, request_matcher,
};
pub use response::{
    Response, ResponseHeadParser, ResponseParser, ResponseRef, parse_response, parse_response_ref,
    response_head_matcher, response_matcher,
};

use crate::matcher::{ErrorKind, MatchError, Matcher};
use crate::parser::{recognize, repeat, skip_while, skip_while1, tag, take_while, take_while1};
use crate::stream::ByteStream;
use std::fmt;
use std::ops::Range;

/// Protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
}

impl Version {
    /// `"HTTP/1.0"` or `"HTTP/1.1"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Limits and validation settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Maximum size of the start line and headers (and, separately, of the trailers),
    /// in bytes (default: 16 KiB).
    pub max_head: usize,
    /// Maximum number of header fields (default: 100).
    pub max_headers: usize,
    /// Maximum body size, in bytes (default: 1 MiB). For chunked bodies this is the
    /// decoded size.
    pub max_body: u64,
    /// Reject HTTP/1.1 requests without exactly one `Host` header, and HTTP/1.0 requests
    /// with several (default: true, as required from servers by RFC 9112).
    pub require_host: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_head: 16 << 10,
            max_headers: 100,
            max_body: 1 << 20,
            require_host: true,
        }
    }
}

/// A header field.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Header {
    /// Field name, as received.
    pub name: String,
    /// Field value without surrounding whitespace. Usually ASCII, but may contain
    /// arbitrary bytes (obs-text), hence not a `String`.
    pub value: Vec<u8>,
}

impl Header {
    /// A header field.
    pub fn new(name: impl Into<String>, value: impl Into<Vec<u8>>) -> Header {
        Header {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// A header field borrowed from the parsed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeaderRef<'a> {
    /// Field name, as received.
    pub name: &'a str,
    /// Field value without surrounding whitespace.
    pub value: &'a [u8],
}

/// Header access shared by all message types.
pub trait Message {
    /// Protocol version.
    fn version(&self) -> Version;

    /// Header fields as `(name, value)` pairs, in the order received.
    fn header_pairs(&self) -> impl Iterator<Item = (&str, &[u8])>;

    /// Value of the first header with a given name (case-insensitive).
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers_named(name).next()
    }

    /// Value of the first header with a given name, if it is valid UTF-8.
    fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Values of all headers with a given name (case-insensitive).
    fn headers_named<'s>(&'s self, name: &str) -> impl Iterator<Item = &'s [u8]> {
        self.header_pairs()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Whether any header with a given name has `token` in its comma-separated list
    /// value (case-insensitive), e.g. `has_token("Connection", "close")`.
    fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers_named(name)
            .flat_map(|v| v.split(|b| *b == b','))
            .any(|t| trim_ows(t).eq_ignore_ascii_case(token.as_bytes()))
    }

    /// Whether the connection stays open after this message, according to the
    /// `Connection` header and the version. (A response body delimited by closing the
    /// connection, [`Framing::UntilClose`], also ends the connection.)
    fn keep_alive(&self) -> bool {
        if self.has_token("Connection", "close") {
            return false;
        }
        match self.version() {
            Version::Http11 => true,
            Version::Http10 => self.has_token("Connection", "keep-alive"),
        }
    }
}

/// The status code to answer a request that failed to parse with (`None` for
/// `Incomplete`, which means more input is needed).
///
/// 431 for a request head that is too large, 413 for a body that is too large, 400 for
/// anything else.
pub fn error_status(e: &MatchError) -> Option<u16> {
    match e.kind() {
        ErrorKind::Incomplete => None,
        ErrorKind::TooLarge if e.context() == Some(BODY) => Some(413),
        ErrorKind::TooLarge => Some(431),
        _ => Some(400),
    }
}

/// Error from encoding an invalid message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeError(&'static str);

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for EncodeError {}

// Error contexts, see `error_status`.
pub(crate) const HEAD: &str = "head";
pub(crate) const BODY: &str = "body";

// Character classes (RFC 9110, section 5.6.2 and 5.5)

macro_rules! class {
    ($f:ident) => {{
        let mut table = [false; 256];
        let mut i = 0;
        while i < 256 {
            table[i] = $f(i as u8);
            i += 1;
        }
        table
    }};
}

const fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

// field-vchar, SP and HTAB (i.e. no CR, LF, NUL and other controls)
const fn field_byte(b: u8) -> bool {
    b == b'\t' || (b >= 0x20 && b != 0x7F)
}

const TCHAR: [bool; 256] = class!(tchar);
const FIELD_BYTE: [bool; 256] = class!(field_byte);

pub(crate) fn is_tchar(b: u8) -> bool {
    TCHAR[b as usize]
}

pub(crate) fn is_field_byte(b: u8) -> bool {
    FIELD_BYTE[b as usize]
}

pub(crate) fn is_visible(b: u8) -> bool {
    (0x21..=0x7E).contains(&b)
}

pub(crate) fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

pub(crate) fn trim_ows(v: &[u8]) -> &[u8] {
    let start = v.iter().position(|b| !is_ows(*b)).unwrap_or(v.len());
    let end = v.iter().rposition(|b| !is_ows(*b)).map_or(start, |i| i + 1);
    &v[start..end]
}

pub(crate) fn crlf() -> impl Matcher<()> {
    tag(b"\r\n")
}

// How the grammar captures fields: copied (for resumable parsing, where consumed bytes
// may be dropped from the buffer), as spans (zero-copy parsing of a slice), or not at all.
pub(crate) trait Capture {
    type Field: Send;
    type Body: Default + Send;

    fn field<F: Fn(u8) -> bool>(f: F) -> impl Matcher<Self::Field>;
    fn field1<F: Fn(u8) -> bool>(f: F, what: &'static str) -> impl Matcher<Self::Field>;
    // bytes of a field that is still buffered
    fn get<'s>(field: &'s Self::Field, bs: &'s ByteStream<'_>) -> &'s [u8];
    // add a decoded piece of body, given as a range of stream offsets
    fn push(body: &mut Self::Body, piece: Range<usize>, bs: &ByteStream<'_>);
}

pub(crate) struct Copied;

impl Capture for Copied {
    type Field = Vec<u8>;
    type Body = Vec<u8>;

    fn field<F: Fn(u8) -> bool>(f: F) -> impl Matcher<Vec<u8>> {
        take_while(f)
    }

    fn field1<F: Fn(u8) -> bool>(f: F, what: &'static str) -> impl Matcher<Vec<u8>> {
        take_while1(f, what)
    }

    fn get<'s>(field: &'s Vec<u8>, _: &'s ByteStream<'_>) -> &'s [u8] {
        field
    }

    fn push(body: &mut Vec<u8>, piece: Range<usize>, bs: &ByteStream<'_>) {
        body.extend_from_slice(bs.slice(piece).expect("piece was just consumed"));
    }
}

pub(crate) struct Spans;

impl Capture for Spans {
    type Field = Range<usize>;
    type Body = Vec<Range<usize>>;

    fn field<F: Fn(u8) -> bool>(f: F) -> impl Matcher<Range<usize>> {
        recognize(skip_while(f))
    }

    fn field1<F: Fn(u8) -> bool>(f: F, what: &'static str) -> impl Matcher<Range<usize>> {
        recognize(skip_while1(f, what))
    }

    fn get<'s>(field: &'s Range<usize>, bs: &'s ByteStream<'_>) -> &'s [u8] {
        bs.slice(field.clone())
            .expect("spans are used only on streams that are never pulled")
    }

    fn push(body: &mut Vec<Range<usize>>, piece: Range<usize>, _: &ByteStream<'_>) {
        body.push(piece);
    }
}

pub(crate) struct Skipped;

impl Capture for Skipped {
    type Field = ();
    type Body = ();

    fn field<F: Fn(u8) -> bool>(f: F) -> impl Matcher<()> {
        skip_while(f)
    }

    fn field1<F: Fn(u8) -> bool>(f: F, what: &'static str) -> impl Matcher<()> {
        skip_while1(f, what)
    }

    fn get<'s>(_: &'s (), _: &'s ByteStream<'_>) -> &'s [u8] {
        &[]
    }

    fn push(_: &mut (), _: Range<usize>, _: &ByteStream<'_>) {}
}

pub(crate) struct RawHeader<F> {
    pub name: F,
    // may have trailing whitespace
    pub value: F,
}

fn header<C: Capture>() -> impl Matcher<RawHeader<C::Field>> {
    C::field1(is_tchar, "header name")
        .then(tag(b":"))
        .then(skip_while(is_ows))
        // stops at CR, LF and other bytes that are not allowed in a field value
        .then(C::field(is_field_byte))
        .then(crlf())
        .map(|((((name, _), _), value), _)| RawHeader { name, value })
}

pub(crate) fn headers<C: Capture>(max: usize) -> impl Matcher<Vec<RawHeader<C::Field>>> {
    repeat(header::<C>()).try_map(move |headers: Vec<_>| {
        if headers.len() > max {
            return Err("too many headers");
        }
        Ok(headers)
    })
}

// trailer section of a chunked body: validated, then dropped
pub(crate) fn trailers() -> impl Matcher<()> {
    repeat(header::<Skipped>()).then(crlf()).map(|_| ())
}

pub(crate) fn version() -> impl Matcher<Version> {
    tag(b"HTTP/1.")
        .then(|bs: &mut ByteStream<'_>| match bs.peek() {
            Some(b'0') => {
                bs.next();
                Ok(Version::Http10)
            }
            Some(b'1') => {
                bs.next();
                Ok(Version::Http11)
            }
            Some(_) => Err(MatchError::invalid(
                bs.offset(),
                "unsupported protocol version",
            )),
            None => Err(MatchError::incomplete(bs.offset(), 1, 0)),
        })
        .map(|(_, v)| v)
}

// Header pairs of a raw head, with values trimmed.
pub(crate) fn pairs<'s, C: Capture>(
    headers: &'s [RawHeader<C::Field>],
    bs: &'s ByteStream<'_>,
) -> impl Iterator<Item = (&'s [u8], &'s [u8])> + Clone {
    headers
        .iter()
        .map(move |h| (C::get(&h.name, bs), trim_ows(C::get(&h.value, bs))))
}

pub(crate) fn owned_headers(raw: Vec<RawHeader<Vec<u8>>>) -> Vec<Header> {
    raw.into_iter()
        .map(|h| {
            let mut value = h.value;
            let end = value.iter().rposition(|b| !is_ows(*b)).map_or(0, |i| i + 1);
            value.truncate(end);
            Header {
                name: ascii(h.name),
                value,
            }
        })
        .collect()
}

pub(crate) fn ref_headers<'a>(
    raw: &[RawHeader<Range<usize>>],
    buf: &'a [u8],
) -> Vec<HeaderRef<'a>> {
    raw.iter()
        .map(|h| HeaderRef {
            name: ascii_ref(&buf[h.name.clone()]),
            value: trim_ows(&buf[h.value.clone()]),
        })
        .collect()
}

// Validated tokens and targets are ASCII.
pub(crate) fn ascii(v: Vec<u8>) -> String {
    String::from_utf8(v).expect("validated ASCII")
}

pub(crate) fn ascii_ref(v: &[u8]) -> &str {
    std::str::from_utf8(v).expect("validated ASCII")
}

// Encoding

pub(crate) fn encode_headers(headers: &[Header], out: &mut Vec<u8>) -> Result<(), EncodeError> {
    for h in headers {
        if h.name.is_empty() || !h.name.bytes().all(is_tchar) {
            return Err(EncodeError("invalid header name"));
        }
        if !h.value.iter().all(|b| is_field_byte(*b)) {
            return Err(EncodeError("invalid header value"));
        }
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(trim_ows(&h.value));
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

pub(crate) fn set_content_length(headers: &mut Vec<Header>, len: usize) {
    headers.retain(|h| {
        !h.name.eq_ignore_ascii_case("Content-Length")
            && !h.name.eq_ignore_ascii_case("Transfer-Encoding")
    });
    headers.push(Header::new("Content-Length", len.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn character_classes() {
        assert!(b"!#$%&'*+-.^_`|~azAZ09".iter().all(|b| is_tchar(*b)));
        assert!(
            !b" \t\r\n\"(),/:;<=>?@[\\]{}\x7f\x80"
                .iter()
                .any(|b| is_tchar(*b))
        );
        assert!(b" \ta~\x80\xff".iter().all(|b| is_field_byte(*b)));
        assert!(!b"\r\n\x00\x1f\x7f".iter().any(|b| is_field_byte(*b)));
        assert_eq!(trim_ows(b" \t a b \t"), b"a b");
        assert_eq!(trim_ows(b"  "), b"");
    }

    #[test]
    fn status_for_errors() {
        let head = MatchError::too_large(0, "x");
        assert_eq!(error_status(&head), Some(431));
        let body = MatchError::too_large(0, "x").with_context(BODY);
        assert_eq!(error_status(&body), Some(413));
        assert_eq!(error_status(&MatchError::incomplete(0, 1, 0)), None);
        assert_eq!(error_status(&MatchError::invalid(0, "x")), Some(400));
    }
}
