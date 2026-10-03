//! Frames ([RFC 6455, section 5](https://www.rfc-editor.org/rfc/rfc6455#section-5)).

use super::WsError;
use crate::matcher::{Boxed, MatchError, Matcher, ReadError, Resumable};
use crate::parser::{advance, bytes, get_u16, recognize};
use crate::stream::ByteStream;

/// Frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpCode {
    /// Continuation of a fragmented message.
    Continuation,
    /// (First fragment of) a text message.
    Text,
    /// (First fragment of) a binary message.
    Binary,
    /// Close.
    Close,
    /// Ping.
    Ping,
    /// Pong.
    Pong,
}

impl OpCode {
    /// The opcode for a 4-bit value (`None` for reserved values).
    pub fn from_u8(code: u8) -> Option<OpCode> {
        Some(match code {
            0 => OpCode::Continuation,
            1 => OpCode::Text,
            2 => OpCode::Binary,
            8 => OpCode::Close,
            9 => OpCode::Ping,
            10 => OpCode::Pong,
            _ => return None,
        })
    }

    /// The 4-bit value.
    pub fn as_u8(self) -> u8 {
        match self {
            OpCode::Continuation => 0,
            OpCode::Text => 1,
            OpCode::Binary => 2,
            OpCode::Close => 8,
            OpCode::Ping => 9,
            OpCode::Pong => 10,
        }
    }

    /// Whether this is a control frame (close, ping, pong).
    pub fn is_control(self) -> bool {
        self.as_u8() & 0x08 != 0
    }
}

/// A frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Whether this is the final fragment of a message.
    pub fin: bool,
    /// Reserved bits RSV1..RSV3 (as the lowest 3 bits), used by extensions.
    pub rsv: u8,
    /// Frame type.
    pub opcode: OpCode,
    /// Masking key, if the payload is masked.
    pub mask: Option<[u8; 4]>,
    /// Payload as on the wire: masked if `mask` is set (see [`Frame::unmask`]).
    pub payload: Vec<u8>,
}

impl Frame {
    /// Final unmasked frame.
    pub fn new(opcode: OpCode, payload: impl Into<Vec<u8>>) -> Frame {
        Frame {
            fin: true,
            rsv: 0,
            opcode,
            mask: None,
            payload: payload.into(),
        }
    }

    /// Final unmasked text frame.
    pub fn text(text: &str) -> Frame {
        Frame::new(OpCode::Text, text)
    }

    /// Final unmasked binary frame.
    pub fn binary(data: impl Into<Vec<u8>>) -> Frame {
        Frame::new(OpCode::Binary, data)
    }

    /// Mask the payload with `key` (frames sent by a client must be masked with a fresh
    /// random key each). Does nothing if the frame is masked already.
    pub fn masked(mut self, key: [u8; 4]) -> Frame {
        if self.mask.is_none() {
            apply_mask(&mut self.payload, key);
            self.mask = Some(key);
        }
        self
    }

    /// Unmask the payload in place.
    pub fn unmask(&mut self) {
        if let Some(key) = self.mask.take() {
            apply_mask(&mut self.payload, key);
        }
    }

    /// Serialize the frame. Fails for frames that are not allowed on the wire: a control
    /// frame that is fragmented or has more than 125 bytes of payload, or reserved bits
    /// out of range.
    pub fn encode(&self) -> Result<Vec<u8>, WsError> {
        let mut out = Vec::with_capacity(self.payload.len() + 14);
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Like [`Frame::encode`], appending to `out` (nothing is appended on error).
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), WsError> {
        if self.rsv > 0x07 {
            return Err(WsError::protocol("reserved bits out of range"));
        }
        if self.opcode.is_control() && (!self.fin || self.payload.len() > 125) {
            return Err(WsError::protocol(
                "control frame must be final and at most 125 bytes",
            ));
        }
        let len = self.payload.len();
        out.reserve(len + 14);
        out.push(((self.fin as u8) << 7) | (self.rsv << 4) | self.opcode.as_u8());
        let mask_bit = if self.mask.is_some() { 0x80u8 } else { 0 };
        if len <= 125 {
            out.push(mask_bit | len as u8);
        } else if len <= u16::MAX as usize {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if let Some(mask) = self.mask {
            out.extend_from_slice(&mask);
        }
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

/// A frame borrowed from the parsed input, see [`parse_frame_ref`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRef<'a> {
    /// Whether this is the final fragment of a message.
    pub fin: bool,
    /// Reserved bits RSV1..RSV3 (as the lowest 3 bits).
    pub rsv: u8,
    /// Frame type.
    pub opcode: OpCode,
    /// Masking key, if the payload is masked.
    pub mask: Option<[u8; 4]>,
    /// Payload as on the wire: masked if `mask` is set.
    pub payload: &'a [u8],
}

impl FrameRef<'_> {
    /// Copy into an owned (still masked) [`Frame`].
    pub fn into_owned(self) -> Frame {
        Frame {
            fin: self.fin,
            rsv: self.rsv,
            opcode: self.opcode,
            mask: self.mask,
            payload: self.payload.to_vec(),
        }
    }
}

/// Mask or unmask (the operation is its own inverse) a payload in place.
pub fn apply_mask(payload: &mut [u8], key: [u8; 4]) {
    let word = u64::from_ne_bytes([
        key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3],
    ]);
    let mut chunks = payload.chunks_exact_mut(8);
    for chunk in &mut chunks {
        let v = u64::from_ne_bytes(chunk.try_into().expect("8 bytes")) ^ word;
        chunk.copy_from_slice(&v.to_ne_bytes());
    }
    for (b, k) in chunks.into_remainder().iter_mut().zip(key.iter().cycle()) {
        *b ^= k;
    }
}

/// Which frames are acceptable with respect to masking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Masking {
    /// Accept both masked and unmasked frames.
    Any,
    /// Accept only masked frames: a server receiving frames from a client.
    Required,
    /// Accept only unmasked frames: a client receiving frames from a server.
    Forbidden,
}

/// Validation settings for frame parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameConfig {
    /// Maximum payload length (default: 16 MiB).
    pub max_payload: u64,
    /// Masking requirement (default: [`Masking::Any`]).
    pub masking: Masking,
    /// Reserved bits that negotiated extensions allow to be set, as a bit mask over
    /// [`Frame::rsv`] (default: none).
    pub allowed_rsv: u8,
}

impl Default for FrameConfig {
    fn default() -> Self {
        FrameConfig {
            max_payload: 16 << 20,
            masking: Masking::Any,
            allowed_rsv: 0,
        }
    }
}

impl FrameConfig {
    /// Settings for a server: frames from clients must be masked.
    pub fn server() -> Self {
        FrameConfig {
            masking: Masking::Required,
            ..FrameConfig::default()
        }
    }

    /// Settings for a client: frames from servers must not be masked.
    pub fn client() -> Self {
        FrameConfig {
            masking: Masking::Forbidden,
            ..FrameConfig::default()
        }
    }
}

#[derive(Clone, Copy)]
struct Head {
    fin: bool,
    rsv: u8,
    opcode: OpCode,
    masked: bool,
    len7: u8,
}

impl Head {
    fn parse(word: u16, cfg: &FrameConfig) -> Result<Head, &'static str> {
        let [b0, b1] = word.to_be_bytes();
        let fin = b0 & 0x80 != 0;
        let rsv = (b0 >> 4) & 0x07;
        let opcode = OpCode::from_u8(b0 & 0x0F).ok_or("reserved opcode")?;
        let masked = b1 & 0x80 != 0;
        let len7 = b1 & 0x7F;
        if rsv & !cfg.allowed_rsv != 0 {
            return Err("reserved bits are set");
        }
        if opcode.is_control() {
            if !fin {
                return Err("fragmented control frame");
            }
            if len7 > 125 {
                return Err("control frame payload longer than 125 bytes");
            }
        }
        match (cfg.masking, masked) {
            (Masking::Required, false) => Err("frame is not masked"),
            (Masking::Forbidden, true) => Err("frame is masked"),
            _ => Ok(Head {
                fin,
                rsv,
                opcode,
                masked,
                len7,
            }),
        }
    }
}

// Frame header: head, payload length and mask.
fn header(cfg: FrameConfig) -> impl Matcher<(Head, u64, Option<[u8; 4]>)> {
    get_u16()
        .try_map(move |word| Head::parse(word, &cfg))
        .then_with(|head| {
            let len7 = head.len7;
            let width = match len7 {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            bytes(width).try_map(move |ext| {
                let len = ext.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
                match width {
                    0 => Ok(len7 as u64),
                    _ if len >> 63 != 0 => Err("most significant bit of 64-bit length is set"),
                    2 if len < 126 => Err("length is not minimally encoded"),
                    8 if len <= u16::MAX as u64 => Err("length is not minimally encoded"),
                    _ => Ok(len),
                }
            })
        })
        .then_with(move |(_, len)| {
            let too_large = *len > cfg.max_payload || usize::try_from(*len).is_err();
            move |bs: &mut ByteStream<'_>| match too_large {
                true => Err(MatchError::too_large(bs.offset(), "payload too large")),
                false => Ok(()),
            }
        })
        .map(|(head_len, _)| head_len)
        .then_with(|(head, _)| bytes(if head.masked { 4 } else { 0 }))
        .map(|((head, len), mask)| {
            let mask = head.masked.then(|| [mask[0], mask[1], mask[2], mask[3]]);
            (head, len, mask)
        })
}

/// Matcher for a single frame, validated according to `cfg`.
pub fn frame_matcher(cfg: FrameConfig) -> impl Matcher<Frame> {
    header(cfg)
        // `bytes` allocates only as the payload arrives, not up-front
        .then_with(|(_, len, _)| bytes(*len as usize))
        .map(|((head, _, mask), payload)| Frame {
            fin: head.fin,
            rsv: head.rsv,
            opcode: head.opcode,
            mask,
            payload,
        })
}

/// One-shot frame parsing. On error the stream is left untouched; `Incomplete` means
/// the frame is not fully buffered yet. See [`FrameParser`] to keep partial progress.
pub fn parse_frame(bs: &mut ByteStream<'_>, cfg: &FrameConfig) -> Result<Frame, MatchError> {
    frame_matcher(*cfg).do_match(bs)
}

/// Zero-copy frame parsing from a slice holding what has been received so far. Returns
/// the frame borrowing from `buf`, and the number of bytes it takes.
///
/// ```
/// use parsed::ws::{Frame, FrameConfig, parse_frame_ref};
///
/// let wire = Frame::text("hi").encode().unwrap();
/// let (frame, len) = parse_frame_ref(&wire, &FrameConfig::default()).unwrap();
/// assert_eq!((frame.payload, len), (&b"hi"[..], 4));
/// ```
pub fn parse_frame_ref<'a>(
    buf: &'a [u8],
    cfg: &FrameConfig,
) -> Result<(FrameRef<'a>, usize), MatchError> {
    let mut bs = ByteStream::partial(buf);
    let m = header(*cfg).then_with(|(_, len, _)| recognize(advance(*len as usize)));
    let ((head, _, mask), payload) = m.do_match(&mut bs)?;
    let frame = FrameRef {
        fin: head.fin,
        rsv: head.rsv,
        opcode: head.opcode,
        mask,
        payload: &buf[payload],
    };
    Ok((frame, bs.offset()))
}

/// Resumable frame parser: on `Incomplete` the progress is kept (and the consumed bytes
/// can be dropped with [`ByteStream::pull`]), and the next call continues from there.
/// Payloads may be larger than the buffer.
pub struct FrameParser(Resumable<Boxed<Frame>, Frame>);

impl FrameParser {
    /// Parser validating frames according to `cfg`.
    pub fn new(cfg: FrameConfig) -> Self {
        FrameParser(Resumable::new(frame_matcher(cfg).boxed()))
    }

    /// Continue parsing the current frame, see [`Resumable::parse`].
    pub fn parse(&mut self, bs: &mut ByteStream<'_>) -> Result<Frame, MatchError> {
        self.0.parse(bs)
    }

    /// Whether a frame is partially parsed.
    pub fn is_started(&self) -> bool {
        self.0.is_started()
    }

    /// Parse the next frame, reading from `reader` as needed; `None` at a clean end of
    /// input. See [`Resumable::read_from`].
    pub fn read_from<R: std::io::Read>(
        &mut self,
        bs: &mut ByteStream<'_>,
        reader: &mut R,
    ) -> Result<Option<Frame>, ReadError> {
        self.0.read_from(bs, reader)
    }
}

impl Default for FrameParser {
    fn default() -> Self {
        FrameParser::new(FrameConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::ErrorKind;
    use crate::testing::feed;

    fn parse(wire: &[u8]) -> Result<Frame, MatchError> {
        parse_frame(&mut ByteStream::borrow(wire), &FrameConfig::default())
    }

    #[test]
    fn known_frames() {
        let frame = parse(&[128 + 9, 128 + 7, 1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16]).unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, OpCode::Ping);
        assert_eq!(frame.mask, Some([1, 2, 3, 4]));
        assert_eq!(frame.payload, vec![10, 11, 12, 13, 14, 15, 16]);

        let frame = parse(&[2, 3, 10, 20, 30]).unwrap();
        assert!(!frame.fin);
        assert_eq!((frame.opcode, frame.mask), (OpCode::Binary, None));

        // "hello!" masked, from RFC-style example
        let mut frame = parse(&[129, 134, 87, 35, 230, 82, 63, 70, 138, 62, 56, 2]).unwrap();
        frame.unmask();
        assert_eq!((frame.opcode, frame.mask), (OpCode::Text, None));
        assert_eq!(frame.payload, b"hello!");
    }

    #[test]
    fn rfc_examples() {
        // RFC 6455, section 5.7
        assert_eq!(
            Frame::text("Hello").encode().unwrap(),
            [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]
        );
        let masked = Frame::text("Hello").masked([0x37, 0xfa, 0x21, 0x3d]);
        assert_eq!(
            masked.encode().unwrap(),
            [
                0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
            ]
        );
        let first = parse(&[0x01, 0x03, 0x48, 0x65, 0x6c]).unwrap();
        assert_eq!(
            (first.fin, first.opcode, &first.payload[..]),
            (false, OpCode::Text, &b"Hel"[..])
        );
        let last = parse(&[0x80, 0x02, 0x6c, 0x6f]).unwrap();
        assert_eq!((last.fin, last.opcode), (true, OpCode::Continuation));
        let wire_256 = parse(&[&[0x82, 0x7E, 0x01, 0x00][..], &[0u8; 256]].concat()).unwrap();
        assert_eq!(wire_256.payload.len(), 256);
    }

    fn frame(len: usize, mask: Option<[u8; 4]>) -> Frame {
        Frame {
            fin: true,
            rsv: 0,
            opcode: OpCode::Binary,
            mask,
            payload: (0..len).map(|i| i as u8).collect(),
        }
    }

    #[test]
    fn round_trip_all_length_encodings() {
        for &len in &[0usize, 1, 125, 126, 127, 65535, 65536, 70000] {
            for &mask in &[None, Some([9, 8, 7, 6])] {
                let f = frame(len, mask);
                let wire = f.encode().unwrap();
                let header = match len {
                    0..=125 => 2,
                    126..=65535 => 4,
                    _ => 10,
                } + if mask.is_some() { 4 } else { 0 };
                assert_eq!(wire.len(), header + len, "len={} mask={:?}", len, mask);
                assert_eq!(parse(&wire).unwrap(), f, "len={}", len);
                let (r, n) = parse_frame_ref(&wire, &FrameConfig::default()).unwrap();
                assert_eq!((r.into_owned(), n), (f.clone(), wire.len()));
                let fed = feed(frame_matcher(FrameConfig::default()), &wire, 5, false);
                assert_eq!(fed.unwrap(), f, "len={}", len);
            }
        }
    }

    #[test]
    fn masking_is_an_involution() {
        for len in [0, 1, 7, 8, 9, 16, 1000] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let mut masked = data.clone();
            apply_mask(&mut masked, [1, 2, 3, 4]);
            let bytewise: Vec<u8> = data
                .iter()
                .zip([1u8, 2, 3, 4].iter().cycle())
                .map(|(a, b)| a ^ b)
                .collect();
            assert_eq!(masked, bytewise);
            apply_mask(&mut masked, [1, 2, 3, 4]);
            assert_eq!(masked, data);
        }
    }

    #[test]
    fn partial_frame_is_incomplete_and_not_consumed() {
        let wire = frame(300, Some([1, 2, 3, 4])).encode().unwrap();
        for cut in 0..wire.len() {
            let mut bs = ByteStream::borrow(&wire[..cut]);
            let e = parse_frame(&mut bs, &FrameConfig::default()).unwrap_err();
            assert!(e.is_incomplete(), "cut={}: {}", cut, e);
            assert_eq!(bs.pos(), 0, "cut={}", cut);
            let e = parse_frame_ref(&wire[..cut], &FrameConfig::default()).unwrap_err();
            assert!(e.is_incomplete(), "ref cut={}: {}", cut, e);
        }
    }

    fn wire_with_len(len: u64) -> Vec<u8> {
        let mut wire = vec![0x82, 127];
        wire.extend_from_slice(&len.to_be_bytes());
        wire
    }

    #[test]
    fn payload_limit() {
        let e = parse(&wire_with_len(1 << 40)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TooLarge);
        assert_eq!(e.to_string(), "at offset 10: payload too large");

        // without a limit, a huge length does not allocate: it waits for the payload
        let cfg = FrameConfig {
            max_payload: u64::MAX,
            ..FrameConfig::default()
        };
        let wire = wire_with_len(1 << 62);
        let mut bs = ByteStream::borrow(&wire);
        assert!(parse_frame(&mut bs, &cfg).unwrap_err().is_incomplete());
    }

    fn rejects(cfg: FrameConfig, wire: &[u8], message: &str) {
        let mut bs = ByteStream::borrow(wire);
        let e = parse_frame(&mut bs, &cfg).unwrap_err();
        assert!(!e.is_incomplete());
        assert!(e.to_string().ends_with(message), "{:?}: {}", wire, e);
        assert_eq!(bs.pos(), 0);
    }

    #[test]
    fn protocol_violations_are_rejected() {
        let d = FrameConfig::default();
        rejects(
            d,
            &wire_with_len(u64::MAX),
            "most significant bit of 64-bit length is set",
        );
        rejects(d, &[0x82, 126, 0, 125], "length is not minimally encoded");
        rejects(d, &wire_with_len(65535), "length is not minimally encoded");
        rejects(d, &[0xC2, 0], "reserved bits are set");
        rejects(d, &[0x83, 0], "reserved opcode");
        rejects(d, &[0x8B, 0], "reserved opcode");
        rejects(d, &[0x09, 0], "fragmented control frame");
        rejects(
            d,
            &[0x89, 126, 0, 200],
            "control frame payload longer than 125 bytes",
        );
        rejects(FrameConfig::server(), &[0x82, 0], "frame is not masked");
        rejects(
            FrameConfig::client(),
            &[0x82, 0x80, 1, 2, 3, 4],
            "frame is masked",
        );

        let deflate = FrameConfig {
            allowed_rsv: 0b100,
            ..d
        };
        let mut bs = ByteStream::borrow(&[0xC2, 0]);
        assert_eq!(parse_frame(&mut bs, &deflate).unwrap().rsv, 0b100);
    }

    #[test]
    fn invalid_frames_are_not_encoded() {
        let mut ping = Frame::new(OpCode::Ping, vec![0; 126]);
        assert!(ping.encode().is_err());
        ping.payload.truncate(125);
        assert!(ping.encode().is_ok());
        ping.fin = false;
        assert!(ping.encode().is_err());
        let mut out = b"x".to_vec();
        assert!(
            Frame {
                rsv: 8,
                ..Frame::text("")
            }
            .encode_into(&mut out)
            .is_err()
        );
        assert_eq!(out, b"x");
    }

    #[test]
    fn frame_parser_across_chunks() {
        let mut wire = frame(1000, Some([5, 6, 7, 8])).encode().unwrap();
        wire.extend(Frame::text("next").encode().unwrap());
        let mut parser = FrameParser::default();
        let mut bs = ByteStream::with_capacity(80);
        let mut frames = vec![];
        for chunk in wire.chunks(64) {
            bs.pull();
            assert_eq!(bs.put(chunk), chunk.len());
            loop {
                match parser.parse(&mut bs) {
                    Ok(f) => frames.push(f),
                    Err(e) if e.is_incomplete() => break,
                    Err(e) => panic!("{}", e),
                }
            }
        }
        assert_eq!(
            frames,
            vec![frame(1000, Some([5, 6, 7, 8])), Frame::text("next")]
        );
    }

    #[test]
    fn chunk_invariance() {
        fn f(data: Vec<u8>, chunk: u8) -> bool {
            let cfg = FrameConfig::default();
            let mut bs = ByteStream::borrow(&data);
            let whole = parse_frame(&mut bs, &cfg);
            if whole.is_err() && bs.pos() != 0 {
                return false;
            }
            let fed = feed(frame_matcher(cfg), &data, chunk as usize, true);
            let zero_copy = parse_frame_ref(&data, &cfg).map(|(f, _)| f.into_owned());
            match (&whole, &fed) {
                (Ok(a), Ok(b)) => a == b && zero_copy.as_ref() == Ok(a),
                (Err(a), Err(b)) => a.kind() == b.kind(),
                _ => false,
            }
        }
        quickcheck::QuickCheck::new()
            .tests(10_000)
            .quickcheck(f as fn(Vec<u8>, u8) -> bool);
    }
}
