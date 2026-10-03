//! Message body framing and decoding.

use super::{BODY, Capture, Config, Version, trailers, trim_ows};
use crate::matcher::{Boxed, BoxedState, MatchError, Matcher};
use crate::parser::limit;
use crate::stream::ByteStream;
use std::marker::PhantomData;
use std::mem;
use std::ops::Range;

/// How the body of a message is delimited
/// ([RFC 9112, section 6.3](https://www.rfc-editor.org/rfc/rfc9112#section-6.3)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// No body.
    Empty,
    /// `Content-Length` bytes.
    Length(u64),
    /// Chunked transfer coding.
    Chunked,
    /// Everything until the connection is closed (responses only).
    UntilClose,
}

// Some(last coding is chunked) if there is a Transfer-Encoding header
fn transfer_coding<'h>(
    pairs: impl Iterator<Item = (&'h [u8], &'h [u8])>,
) -> Result<Option<bool>, &'static str> {
    let mut codings = None;
    let mut chunked = false;
    for (_, value) in pairs.filter(|(n, _)| n.eq_ignore_ascii_case(b"Transfer-Encoding")) {
        let count = codings.get_or_insert(0usize);
        for coding in value.split(|b| *b == b',').map(trim_ows) {
            if coding.is_empty() {
                continue;
            }
            let name = trim_ows(coding.split(|b| *b == b';').next().unwrap_or_default());
            if name.is_empty() || !name.iter().all(|b| super::is_tchar(*b)) {
                return Err("invalid Transfer-Encoding");
            }
            if chunked {
                return Err("chunked is not the last transfer coding");
            }
            chunked = name.eq_ignore_ascii_case(b"chunked");
            *count += 1;
        }
    }
    match codings {
        Some(0) => Err("empty Transfer-Encoding"),
        Some(_) => Ok(Some(chunked)),
        None => Ok(None),
    }
}

fn content_length<'h>(
    pairs: impl Iterator<Item = (&'h [u8], &'h [u8])>,
) -> Result<Option<u64>, &'static str> {
    let mut length = None;
    for (_, value) in pairs.filter(|(n, _)| n.eq_ignore_ascii_case(b"Content-Length")) {
        if value.is_empty() || !value.iter().all(|b| b.is_ascii_digit()) {
            return Err("invalid Content-Length");
        }
        let n = value
            .iter()
            .try_fold(0u64, |acc, b| {
                acc.checked_mul(10)?.checked_add((b - b'0') as u64)
            })
            .ok_or("invalid Content-Length")?;
        if length.is_some_and(|m| m != n) {
            return Err("conflicting Content-Length headers");
        }
        length = Some(n);
    }
    Ok(length)
}

pub(crate) fn request_framing<'h>(
    version: Version,
    pairs: impl Iterator<Item = (&'h [u8], &'h [u8])> + Clone,
    require_host: bool,
) -> Result<Framing, &'static str> {
    if require_host {
        let hosts = pairs
            .clone()
            .filter(|(n, _)| n.eq_ignore_ascii_case(b"Host"))
            .count();
        match (version, hosts) {
            (_, 2..) => return Err("multiple Host headers"),
            (Version::Http11, 0) => return Err("missing Host header"),
            _ => {}
        }
    }
    let te = transfer_coding(pairs.clone())?;
    let cl = content_length(pairs)?;
    Ok(match (te, cl) {
        (Some(_), Some(_)) => return Err("both Transfer-Encoding and Content-Length are present"),
        (Some(_), None) if version == Version::Http10 => {
            return Err("Transfer-Encoding in an HTTP/1.0 request");
        }
        (Some(true), None) => Framing::Chunked,
        (Some(false), None) => return Err("unsupported Transfer-Encoding"),
        (None, Some(0) | None) => Framing::Empty,
        (None, Some(n)) => Framing::Length(n),
    })
}

pub(crate) fn response_framing<'h>(
    request_method: &[u8],
    status: u16,
    pairs: impl Iterator<Item = (&'h [u8], &'h [u8])> + Clone,
) -> Result<Framing, &'static str> {
    if request_method == b"HEAD" || status < 200 || status == 204 || status == 304 {
        return Ok(Framing::Empty);
    }
    if request_method == b"CONNECT" && status < 300 {
        // the connection becomes a tunnel
        return Ok(Framing::Empty);
    }
    let te = transfer_coding(pairs.clone())?;
    let cl = content_length(pairs)?;
    Ok(match (te, cl) {
        (Some(_), Some(_)) => return Err("both Transfer-Encoding and Content-Length are present"),
        (Some(true), None) => Framing::Chunked,
        (Some(false), None) => Framing::UntilClose,
        (None, Some(0)) => Framing::Empty,
        (None, Some(n)) => Framing::Length(n),
        (None, None) => Framing::UntilClose,
    })
}

// Longest chunk size line, including extensions.
const MAX_CHUNK_LINE: usize = 4096;

#[derive(Default)]
enum Phase {
    #[default]
    Start,
    Length(u64),
    UntilClose,
    // chunk size line: size digits, extensions, LF
    Size {
        value: u64,
        digits: usize,
    },
    Ext {
        len: usize,
    },
    SizeLf,
    Data(u64),
    DataCr,
    DataLf,
    Trailers,
    Done,
}

// Progress of decoding a body; resumable at any byte.
#[derive(Default)]
pub(crate) struct DecodeState {
    phase: Phase,
    decoded: u64,
    size: u64,
    trailers: Option<(Boxed<()>, BoxedState)>,
}

#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub max_body: u64,
    pub max_trailers: usize,
}

impl Limits {
    pub(crate) fn of(cfg: &Config) -> Limits {
        Limits {
            max_body: cfg.max_body,
            max_trailers: cfg.max_head,
        }
    }
}

fn expect(bs: &mut ByteStream<'_>, byte: u8) -> Result<(), MatchError> {
    match bs.peek() {
        Some(b) if b == byte => {
            bs.next();
            Ok(())
        }
        found @ Some(_) => Err(MatchError::unexpected_byte(bs.offset(), found, byte)),
        None => Err(MatchError::incomplete(bs.offset(), 1, 0)),
    }
}

fn too_large(bs: &ByteStream<'_>) -> MatchError {
    MatchError::too_large(bs.offset(), "body too large")
}

impl DecodeState {
    fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done)
    }

    // Consume the next piece of body data, returning its range of stream offsets, or
    // `None` at the end of the body.
    fn next(
        &mut self,
        framing: Framing,
        limits: Limits,
        bs: &mut ByteStream<'_>,
    ) -> Result<Option<Range<usize>>, MatchError> {
        loop {
            match &mut self.phase {
                Phase::Start => {
                    self.phase = match framing {
                        Framing::Empty => Phase::Done,
                        Framing::Length(n) if n > limits.max_body => return Err(too_large(bs)),
                        Framing::Length(n) => Phase::Length(n),
                        Framing::UntilClose => Phase::UntilClose,
                        Framing::Chunked => Phase::Size {
                            value: 0,
                            digits: 0,
                        },
                    }
                }
                Phase::Length(0) | Phase::Data(0) => {
                    self.phase = match self.phase {
                        Phase::Length(_) => Phase::Done,
                        _ => Phase::DataCr,
                    }
                }
                Phase::Length(left) | Phase::Data(left) => {
                    let start = bs.offset();
                    let n = bs.skip(usize::try_from(*left).unwrap_or(usize::MAX));
                    if n == 0 {
                        let left = usize::try_from(*left).unwrap_or(usize::MAX);
                        return Err(MatchError::incomplete(start, left, 0));
                    }
                    *left -= n as u64;
                    return Ok(Some(start..start + n));
                }
                Phase::UntilClose => {
                    let start = bs.offset();
                    let n = bs.remaining();
                    if n == 0 {
                        if bs.is_closed() {
                            self.phase = Phase::Done;
                            continue;
                        }
                        return Err(MatchError::incomplete(start, 1, 0));
                    }
                    if self.decoded + n as u64 > limits.max_body {
                        return Err(too_large(bs));
                    }
                    self.decoded += n as u64;
                    bs.skip(n);
                    return Ok(Some(start..start + n));
                }
                Phase::Size { value, digits } => match bs.peek() {
                    Some(b) if b.is_ascii_hexdigit() => {
                        if *value > u64::MAX >> 4 {
                            return Err(MatchError::invalid(bs.offset(), "chunk size too large"));
                        }
                        if *digits >= MAX_CHUNK_LINE {
                            return Err(MatchError::invalid(bs.offset(), "chunk line too long"));
                        }
                        *value = (*value << 4) | (b as char).to_digit(16).unwrap() as u64;
                        *digits += 1;
                        bs.next();
                    }
                    Some(_) if *digits == 0 => {
                        return Err(MatchError::unexpected(bs.offset(), bs.peek(), "chunk size"));
                    }
                    Some(b) => {
                        self.size = *value;
                        let len = *digits;
                        match b {
                            b'\r' => {
                                bs.next();
                                self.phase = Phase::SizeLf;
                            }
                            // chunk extensions (ignored)
                            b';' | b' ' | b'\t' => self.phase = Phase::Ext { len },
                            _ => {
                                return Err(MatchError::unexpected(
                                    bs.offset(),
                                    Some(b),
                                    "chunk extension or CRLF",
                                ));
                            }
                        }
                    }
                    None => return Err(MatchError::incomplete(bs.offset(), 1, 0)),
                },
                Phase::Ext { len } => {
                    let pos = bs.pos();
                    let end = bs.find_single(|b| !super::is_field_byte(*b));
                    let n = end.map_or(bs.remaining(), |i| i - pos);
                    *len += n;
                    if *len > MAX_CHUNK_LINE {
                        return Err(MatchError::invalid(bs.offset(), "chunk line too long"));
                    }
                    bs.skip(n);
                    match bs.peek() {
                        None => return Err(MatchError::incomplete(bs.offset(), 1, 0)),
                        Some(b'\r') => {
                            bs.next();
                            self.phase = Phase::SizeLf;
                        }
                        found => {
                            return Err(MatchError::unexpected(
                                bs.offset(),
                                found,
                                "valid chunk extension",
                            ));
                        }
                    }
                }
                Phase::SizeLf => {
                    expect(bs, b'\n')?;
                    if self.size == 0 {
                        self.phase = Phase::Trailers;
                    } else if self.decoded.saturating_add(self.size) > limits.max_body {
                        return Err(too_large(bs));
                    } else {
                        self.decoded += self.size;
                        self.phase = Phase::Data(self.size);
                    }
                }
                Phase::DataCr => {
                    expect(bs, b'\r')?;
                    self.phase = Phase::DataLf;
                }
                Phase::DataLf => {
                    expect(bs, b'\n')?;
                    self.phase = Phase::Size {
                        value: 0,
                        digits: 0,
                    };
                }
                Phase::Trailers => {
                    let (m, state) = self.trailers.get_or_insert_with(|| {
                        (
                            limit(limits.max_trailers, trailers()).boxed(),
                            BoxedState::default(),
                        )
                    });
                    m.resume(state, bs)?;
                    self.trailers = None;
                    self.phase = Phase::Done;
                }
                Phase::Done => return Ok(None),
            }
        }
    }
}

/// Append `data` as one chunk of a chunked body. Empty data appends nothing (an empty
/// chunk would end the body, see [`encode_last_chunk`]).
///
/// ```
/// use parsed::http::{encode_chunk, encode_last_chunk};
///
/// let mut body = Vec::new();
/// encode_chunk(b"hello", &mut body);
/// encode_last_chunk(&mut body);
/// assert_eq!(body, b"5\r\nhello\r\n0\r\n\r\n");
/// ```
pub fn encode_chunk(data: &[u8], out: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }
    out.extend_from_slice(format!("{:X}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// Append the last chunk (with no trailers), ending a chunked body.
pub fn encode_last_chunk(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0\r\n\r\n");
}

/// Streaming body decoder: yields the body in pieces borrowed from the buffer (for a
/// chunked body: the chunk data, without framing), so bodies of any size are processed
/// in constant memory.
///
/// ```
/// use parsed::http::{BodyDecoder, Config, Framing};
/// use parsed::stream::ByteStream;
///
/// let mut decoder = BodyDecoder::new(Framing::Chunked, &Config::default());
/// let mut body = Vec::new();
/// let mut bs = ByteStream::with_capacity(64);
/// for part in [&b"5\r\nhel"[..], b"lo\r\n0\r\n\r\n"] {
///     bs.pull();
///     bs.put(part);
///     loop {
///         match decoder.decode(&mut bs) {
///             Ok(Some(piece)) => body.extend_from_slice(piece),
///             Ok(None) => break, // end of body
///             Err(e) if e.is_incomplete() => break, // wait for more input
///             Err(e) => panic!("{}", e),
///         }
///     }
/// }
/// assert!(decoder.is_done());
/// assert_eq!(body, b"hello");
/// ```
pub struct BodyDecoder {
    framing: Framing,
    limits: Limits,
    state: DecodeState,
}

impl BodyDecoder {
    /// Decoder for a body with the given framing, bounded by `cfg.max_body` (and
    /// `cfg.max_head` for trailers).
    pub fn new(framing: Framing, cfg: &Config) -> Self {
        BodyDecoder {
            framing,
            limits: Limits::of(cfg),
            state: DecodeState::default(),
        }
    }

    /// Next piece of the body (`Some`, valid until the stream is modified), or `None` at
    /// the end of the body. With [`Framing::UntilClose`] the body ends when the stream
    /// is closed ([`ByteStream::close`]).
    ///
    /// On `Incomplete` the progress is kept, and consumed bytes can be dropped with
    /// [`ByteStream::pull`]. After another error the body is invalid.
    pub fn decode<'s>(
        &mut self,
        bs: &'s mut ByteStream<'_>,
    ) -> Result<Option<&'s [u8]>, MatchError> {
        let piece = self
            .state
            .next(self.framing, self.limits, bs)
            .map_err(|e| e.with_context(BODY))?;
        let bs: &'s ByteStream<'_> = bs;
        Ok(piece.map(|range| bs.slice(range).expect("piece was just consumed")))
    }

    /// Whether the whole body has been decoded.
    pub fn is_done(&self) -> bool {
        self.state.is_done()
    }

    /// Number of body bytes accounted for so far (for chunked bodies, including the
    /// current chunk).
    pub fn decoded(&self) -> u64 {
        self.state.decoded
    }
}

/// Matcher for a whole body, accumulated as captured by `C`.
pub(crate) struct BodyMatcher<C> {
    framing: Framing,
    limits: Limits,
    phantom: PhantomData<fn() -> C>,
}

impl<C> BodyMatcher<C> {
    pub(crate) fn new(framing: Framing, cfg: &Config) -> Self {
        BodyMatcher {
            framing,
            limits: Limits::of(cfg),
            phantom: PhantomData,
        }
    }
}

impl<C: Capture> Matcher<C::Body> for BodyMatcher<C> {
    type State = (DecodeState, C::Body);

    fn resume(
        &self,
        state: &mut Self::State,
        bs: &mut ByteStream<'_>,
    ) -> Result<C::Body, MatchError> {
        loop {
            match state.0.next(self.framing, self.limits, bs)? {
                Some(piece) => C::push(&mut state.1, piece, bs),
                None => return Ok(mem::take(state).1),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Copied;
    use crate::parser::Applicator;
    use crate::testing::feed;

    fn pairs<'h>(
        h: &'h [(&'h str, &'h str)],
    ) -> impl Iterator<Item = (&'h [u8], &'h [u8])> + Clone {
        h.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes()))
    }

    #[test]
    fn request_framing_rules() {
        let f = |v, h: &[(&str, &str)]| request_framing(v, pairs(h), true);
        use Version::*;
        let host = ("Host", "a");
        assert_eq!(f(Http11, &[host]), Ok(Framing::Empty));
        assert_eq!(
            f(Http11, &[host, ("Content-Length", "0")]),
            Ok(Framing::Empty)
        );
        assert_eq!(
            f(Http11, &[host, ("content-length", "12")]),
            Ok(Framing::Length(12))
        );
        assert_eq!(
            f(Http11, &[host, ("Transfer-Encoding", "gzip, chunked")]),
            Ok(Framing::Chunked)
        );
        assert_eq!(
            f(
                Http11,
                &[
                    host,
                    ("Transfer-Encoding", "gzip"),
                    ("Transfer-Encoding", "chunked")
                ]
            ),
            Ok(Framing::Chunked)
        );
        assert_eq!(f(Http10, &[]), Ok(Framing::Empty));
        for (v, h, err) in [
            (Http11, &[][..], "missing Host header"),
            (Http11, &[host, host][..], "multiple Host headers"),
            (
                Http11,
                &[host, ("Transfer-Encoding", "gzip")][..],
                "unsupported Transfer-Encoding",
            ),
            (
                Http11,
                &[host, ("Transfer-Encoding", "chunked, gzip")],
                "chunked is not the last transfer coding",
            ),
            (
                Http11,
                &[host, ("Transfer-Encoding", "chunked, chunked")],
                "chunked is not the last transfer coding",
            ),
            (
                Http11,
                &[host, ("Transfer-Encoding", " , ")],
                "empty Transfer-Encoding",
            ),
            (
                Http11,
                &[host, ("Transfer-Encoding", "chu nked")],
                "invalid Transfer-Encoding",
            ),
            (
                Http10,
                &[("Transfer-Encoding", "chunked")],
                "Transfer-Encoding in an HTTP/1.0 request",
            ),
            (
                Http11,
                &[
                    host,
                    ("Transfer-Encoding", "chunked"),
                    ("Content-Length", "1"),
                ],
                "both Transfer-Encoding and Content-Length are present",
            ),
            (
                Http11,
                &[host, ("Content-Length", "1"), ("Content-Length", "2")],
                "conflicting Content-Length headers",
            ),
            (
                Http11,
                &[host, ("Content-Length", "1, 1")],
                "invalid Content-Length",
            ),
            (
                Http11,
                &[host, ("Content-Length", "+1")],
                "invalid Content-Length",
            ),
            (
                Http11,
                &[host, ("Content-Length", "")],
                "invalid Content-Length",
            ),
            (
                Http11,
                &[host, ("Content-Length", "99999999999999999999")],
                "invalid Content-Length",
            ),
        ] {
            assert_eq!(f(v, h), Err(err), "{:?}", h);
        }
        assert_eq!(
            request_framing(Http11, pairs(&[]), false),
            Ok(Framing::Empty)
        );
    }

    #[test]
    fn response_framing_rules() {
        let f = |m: &str, s, h: &[(&str, &str)]| response_framing(m.as_bytes(), s, pairs(h));
        let cl = ("Content-Length", "5");
        assert_eq!(f("GET", 200, &[cl]), Ok(Framing::Length(5)));
        assert_eq!(f("HEAD", 200, &[cl]), Ok(Framing::Empty));
        for status in [100, 101, 199, 204, 304] {
            assert_eq!(f("GET", status, &[cl]), Ok(Framing::Empty), "{}", status);
        }
        assert_eq!(f("CONNECT", 200, &[]), Ok(Framing::Empty));
        assert_eq!(f("CONNECT", 407, &[cl]), Ok(Framing::Length(5)));
        assert_eq!(f("GET", 200, &[]), Ok(Framing::UntilClose));
        assert_eq!(
            f("GET", 200, &[("Transfer-Encoding", "chunked")]),
            Ok(Framing::Chunked)
        );
        assert_eq!(
            f("GET", 200, &[("Transfer-Encoding", "gzip")]),
            Ok(Framing::UntilClose)
        );
        assert!(f("GET", 200, &[("Transfer-Encoding", "chunked"), cl]).is_err());
    }

    fn body(framing: Framing, input: &[u8]) -> Result<Vec<u8>, MatchError> {
        ByteStream::borrow(input).apply(BodyMatcher::<Copied>::new(framing, &Config::default()))
    }

    #[test]
    fn chunked_decoding() {
        let wire = b"5\r\nhello\r\n7;a=b;c=\"d\"\r\n, world\r\nA \t\r\n0123456789\r\n0\r\nT: 1\r\nU:2\r\n\r\n";
        assert_eq!(
            body(Framing::Chunked, wire).unwrap(),
            b"hello, world0123456789"
        );
        for chunk in 1..12 {
            let m = BodyMatcher::<Copied>::new(Framing::Chunked, &Config::default());
            assert_eq!(
                feed(m, wire, chunk, false).unwrap(),
                b"hello, world0123456789"
            );
        }
        for bad in [
            &b"x\r\n"[..],
            b"5\r\nhelloX\r\n",
            b"5\nhello\r\n0\r\n\r\n",
            b"5\r\nhello\r\n0\r\nbad trailer\r\n\r\n",
            b"5x\r\n",
            b"5;\x00\r\n",
            b"10000000000000000\r\n",
        ] {
            let e = body(Framing::Chunked, bad).unwrap_err();
            assert!(!e.is_incomplete(), "{:?}: {}", bad, e);
        }
        let long_ext = format!("1;{}\r\na\r\n0\r\n\r\n", "x".repeat(5000));
        assert!(
            body(Framing::Chunked, long_ext.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("chunk line too long")
        );
    }

    #[test]
    fn chunk_encoding_round_trip() {
        let mut wire = Vec::new();
        for part in [&b"a"[..], b"", &[7u8; 300], b"xyz"] {
            encode_chunk(part, &mut wire);
        }
        encode_last_chunk(&mut wire);
        let expected = [&b"a"[..], &[7u8; 300], b"xyz"].concat();
        assert_eq!(body(Framing::Chunked, &wire).unwrap(), expected);
    }

    #[test]
    fn body_limits() {
        let cfg = Config {
            max_body: 10,
            ..Config::default()
        };
        let m = |f| BodyMatcher::<Copied>::new(f, &cfg);
        let e = ByteStream::borrow(b"")
            .apply(m(Framing::Length(11)))
            .unwrap_err();
        assert_eq!(e.kind(), crate::matcher::ErrorKind::TooLarge);
        let e = ByteStream::borrow(b"6\r\nabcdef\r\n5\r\nabcde\r\n0\r\n\r\n")
            .apply(m(Framing::Chunked))
            .unwrap_err();
        assert_eq!(e.kind(), crate::matcher::ErrorKind::TooLarge);
        let e = ByteStream::borrow(&[0; 11])
            .apply(m(Framing::UntilClose))
            .unwrap_err();
        assert_eq!(e.kind(), crate::matcher::ErrorKind::TooLarge);
        assert_eq!(
            ByteStream::borrow(&[7; 10])
                .apply(m(Framing::UntilClose))
                .unwrap(),
            [7; 10]
        );
    }

    #[test]
    fn until_close_needs_closed_stream() {
        let m = BodyMatcher::<Copied>::new(Framing::UntilClose, &Config::default());
        assert!(
            ByteStream::partial(b"abc")
                .apply(m)
                .unwrap_err()
                .is_incomplete()
        );
    }

    #[test]
    fn decoder_yields_borrowed_pieces() {
        let wire = b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let mut bs = ByteStream::borrow(wire);
        let mut decoder = BodyDecoder::new(Framing::Chunked, &Config::default());
        let first = decoder.decode(&mut bs).unwrap().unwrap();
        assert_eq!(first, b"abc");
        assert_eq!(first.as_ptr(), wire[3..].as_ptr(), "zero-copy");
        assert_eq!(decoder.decode(&mut bs).unwrap().unwrap(), b"de");
        assert_eq!(decoder.decode(&mut bs).unwrap(), None);
        assert!(decoder.is_done());
        assert_eq!(bs.remaining(), 0);

        let mut bs = ByteStream::borrow(b"x");
        let mut decoder = BodyDecoder::new(Framing::Chunked, &Config::default());
        assert_eq!(decoder.decode(&mut bs).unwrap_err().context(), Some(BODY));
    }
}
