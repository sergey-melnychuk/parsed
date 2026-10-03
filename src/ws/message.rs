//! Messages: reassembly of fragmented frames, validation, encoding.

use super::{Frame, FrameConfig, FrameParser, OpCode, WsError, WsErrorKind};
use crate::matcher::ReadError;
use crate::stream::ByteStream;

/// Payload of a close frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    /// Status code, e.g. 1000 (normal closure).
    pub code: u16,
    /// Reason, possibly empty.
    pub reason: String,
}

/// A message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Text message.
    Text(String),
    /// Binary message.
    Binary(Vec<u8>),
    /// Ping, to be answered with a pong with the same payload.
    Ping(Vec<u8>),
    /// Pong.
    Pong(Vec<u8>),
    /// Close, to be answered with a close frame (echoing the code) unless one was sent.
    Close(Option<CloseFrame>),
}

// Close codes that may appear on the wire (RFC 6455, section 7.4, and the IANA registry).
fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

impl Message {
    fn opcode(&self) -> OpCode {
        match self {
            Message::Text(_) => OpCode::Text,
            Message::Binary(_) => OpCode::Binary,
            Message::Ping(_) => OpCode::Ping,
            Message::Pong(_) => OpCode::Pong,
            Message::Close(_) => OpCode::Close,
        }
    }

    fn payload(&self) -> Result<Vec<u8>, WsError> {
        Ok(match self {
            Message::Text(text) => text.as_bytes().to_vec(),
            Message::Binary(data) | Message::Ping(data) | Message::Pong(data) => data.clone(),
            Message::Close(None) => Vec::new(),
            Message::Close(Some(close)) => {
                if !valid_close_code(close.code) {
                    return Err(WsError::protocol("invalid close code"));
                }
                let mut payload = close.code.to_be_bytes().to_vec();
                payload.extend_from_slice(close.reason.as_bytes());
                payload
            }
        })
    }

    /// The message as a single frame, masked with `mask` if given (a client must mask
    /// every frame with a fresh random key). Fails for control messages with a payload
    /// over 125 bytes, and close frames with an invalid code.
    pub fn encode(&self, mask: Option<[u8; 4]>) -> Result<Vec<u8>, WsError> {
        let mut frame = Frame::new(self.opcode(), self.payload()?);
        if let Some(key) = mask {
            frame = frame.masked(key);
        }
        frame.encode()
    }

    /// The message as unmasked frames with payloads of at most `max_payload` bytes (at
    /// least one frame; control messages are never fragmented). Mask each frame with
    /// [`Frame::masked`] before sending, if sending as a client.
    pub fn fragments(&self, max_payload: usize) -> Result<Vec<Frame>, WsError> {
        let opcode = self.opcode();
        let payload = self.payload()?;
        if opcode.is_control() {
            if payload.len() > 125 {
                return Err(WsError::protocol(
                    "control frame payload longer than 125 bytes",
                ));
            }
            return Ok(vec![Frame::new(opcode, payload)]);
        }
        let max = max_payload.max(1);
        let count = payload.len().div_ceil(max).max(1);
        Ok((0..count)
            .map(|i| {
                let part =
                    &payload[(i * max).min(payload.len())..((i + 1) * max).min(payload.len())];
                Frame {
                    fin: i + 1 == count,
                    rsv: 0,
                    opcode: if i == 0 { opcode } else { OpCode::Continuation },
                    mask: None,
                    payload: part.to_vec(),
                }
            })
            .collect())
    }
}

/// Settings for reading messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageConfig {
    /// Frame validation (default: [`FrameConfig::default`]). The frame payload limit
    /// applies to each fragment.
    pub frame: FrameConfig,
    /// Maximum size of a reassembled message (default: 16 MiB).
    pub max_message: usize,
}

impl Default for MessageConfig {
    fn default() -> Self {
        MessageConfig {
            frame: FrameConfig::default(),
            max_message: 16 << 20,
        }
    }
}

impl MessageConfig {
    /// Settings for a server: frames from clients must be masked.
    pub fn server() -> Self {
        MessageConfig {
            frame: FrameConfig::server(),
            ..MessageConfig::default()
        }
    }

    /// Settings for a client: frames from servers must not be masked.
    pub fn client() -> Self {
        MessageConfig {
            frame: FrameConfig::client(),
            ..MessageConfig::default()
        }
    }
}

struct Partial {
    opcode: OpCode,
    data: Vec<u8>,
    // prefix of `data` known to be valid UTF-8 (text messages)
    checked: usize,
}

impl Partial {
    // Validate the new part of a text message as it arrives, so invalid text fails fast.
    fn check_utf8(&mut self, fin: bool) -> Result<(), WsError> {
        if self.opcode != OpCode::Text {
            return Ok(());
        }
        match std::str::from_utf8(&self.data[self.checked..]) {
            Ok(_) => self.checked = self.data.len(),
            // a code point split across fragments
            Err(e) if e.error_len().is_none() && !fin => self.checked += e.valid_up_to(),
            Err(_) => {
                return Err(WsError::new(
                    WsErrorKind::InvalidData,
                    "invalid UTF-8 in text message",
                ));
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<Message, WsError> {
        Ok(match self.opcode {
            OpCode::Text => Message::Text(String::from_utf8(self.data).map_err(|_| {
                WsError::new(WsErrorKind::InvalidData, "invalid UTF-8 in text message")
            })?),
            _ => Message::Binary(self.data),
        })
    }
}

fn close_frame(payload: Vec<u8>) -> Result<Option<CloseFrame>, WsError> {
    match payload.len() {
        0 => Ok(None),
        1 => Err(WsError::protocol("close frame payload of 1 byte")),
        _ => {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            if !valid_close_code(code) {
                return Err(WsError::protocol("invalid close code"));
            }
            let reason = String::from_utf8(payload[2..].to_vec()).map_err(|_| {
                WsError::new(WsErrorKind::InvalidData, "invalid UTF-8 in close reason")
            })?;
            Ok(Some(CloseFrame { code, reason }))
        }
    }
}

/// Reads whole messages from a stream of frames: reassembles fragmented messages,
/// delivers control frames as they arrive (also in between fragments), unmasks
/// payloads, and validates the protocol. Resumable like [`FrameParser`].
///
/// After an error (other than `Incomplete`) the connection should be failed with the
/// error's [`close_code`](WsError::close_code). After a close message, reading further
/// frames is an error.
///
/// ```
/// use parsed::stream::ByteStream;
/// use parsed::ws::{Message, MessageConfig, MessageReader};
///
/// let mut wire = Vec::new();
/// for frame in Message::Text("hello".into()).fragments(2).unwrap() {
///     wire.extend(frame.masked([1, 2, 3, 4]).encode().unwrap());
/// }
/// let mut reader = MessageReader::new(MessageConfig::server());
/// let mut bs = ByteStream::borrow(&wire);
/// assert_eq!(reader.read(&mut bs).unwrap(), Message::Text("hello".into()));
/// ```
pub struct MessageReader {
    frames: FrameParser,
    max_message: usize,
    partial: Option<Partial>,
    closed: bool,
}

impl MessageReader {
    /// Reader validating according to `cfg`.
    pub fn new(cfg: MessageConfig) -> Self {
        MessageReader {
            frames: FrameParser::new(cfg.frame),
            max_message: cfg.max_message,
            partial: None,
            closed: false,
        }
    }

    /// Whether a close message was read.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Read the next message, reading from `reader` into `bs` as needed (see
    /// [`Resumable::read_from`](crate::matcher::Resumable::read_from)):
    ///
    /// - `Ok(Some(message))`: the next message;
    /// - `Ok(None)`: the input ended cleanly between messages, or a close message was read
    ///   before;
    /// - `Err(ReadError::Truncated(_))`: the input ended within a frame or a fragmented
    ///   message;
    /// - `Err(ReadError::Parse(e))`: a protocol violation, to fail the connection with
    ///   `e.close_code()`;
    /// - `Err(ReadError::Io(_))`: reading failed; the progress is kept (e.g. to retry on
    ///   `WouldBlock`).
    pub fn read_from<R: std::io::Read>(
        &mut self,
        bs: &mut ByteStream<'_>,
        reader: &mut R,
    ) -> Result<Option<Message>, ReadError<WsError>> {
        loop {
            if self.closed {
                return Ok(None);
            }
            match self.read(bs) {
                Ok(message) => return Ok(Some(message)),
                Err(e) if e.is_incomplete() && bs.is_closed() => {
                    let clean =
                        self.partial.is_none() && !self.frames.is_started() && bs.remaining() == 0;
                    if clean {
                        return Ok(None);
                    }
                    self.partial = None;
                    return Err(ReadError::Truncated(e));
                }
                Err(e) if e.is_incomplete() => {
                    bs.pull();
                    bs.read_from(reader)?;
                }
                Err(e) => return Err(ReadError::Parse(e)),
            }
        }
    }

    /// Read the next message. `Incomplete` means more input is needed (the progress is
    /// kept, and consumed bytes can be dropped with [`ByteStream::pull`]). See
    /// [`MessageReader::read_from`] for a loop that also reads the input.
    pub fn read(&mut self, bs: &mut ByteStream<'_>) -> Result<Message, WsError> {
        loop {
            if self.closed {
                return Err(WsError::new(WsErrorKind::Closed, "frame after close"));
            }
            let mut frame = self.frames.parse(bs)?;
            frame.unmask();
            match frame.opcode {
                OpCode::Ping => return Ok(Message::Ping(frame.payload)),
                OpCode::Pong => return Ok(Message::Pong(frame.payload)),
                OpCode::Close => {
                    self.closed = true;
                    return Ok(Message::Close(close_frame(frame.payload)?));
                }
                OpCode::Text | OpCode::Binary if self.partial.is_some() => {
                    return Err(WsError::protocol(
                        "new message before the previous one is finished",
                    ));
                }
                OpCode::Continuation if self.partial.is_none() => {
                    return Err(WsError::protocol("continuation frame without a message"));
                }
                _ => {}
            }
            let partial = self.partial.get_or_insert_with(|| Partial {
                opcode: frame.opcode,
                data: Vec::new(),
                checked: 0,
            });
            if partial.data.len() + frame.payload.len() > self.max_message {
                self.partial = None;
                return Err(WsError::new(WsErrorKind::TooLarge, "message too large"));
            }
            if partial.data.is_empty() {
                partial.data = frame.payload;
            } else {
                partial.data.extend_from_slice(&frame.payload);
            }
            if let Err(e) = partial.check_utf8(frame.fin) {
                self.partial = None;
                return Err(e);
            }
            if frame.fin {
                return self.partial.take().expect("partial message").finish();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(frames: &[Frame]) -> Vec<u8> {
        frames.iter().flat_map(|f| f.encode().unwrap()).collect()
    }

    fn read_all(wire: &[u8], cfg: MessageConfig) -> Vec<Result<Message, WsError>> {
        let mut reader = MessageReader::new(cfg);
        let mut bs = ByteStream::borrow(wire);
        let mut out = vec![];
        loop {
            match reader.read(&mut bs) {
                Err(e) if e.is_incomplete() => return out,
                r => {
                    let stop = r.is_err();
                    out.push(r);
                    if stop {
                        return out;
                    }
                }
            }
        }
    }

    fn frag(fin: bool, opcode: OpCode, payload: &[u8]) -> Frame {
        Frame {
            fin,
            ..Frame::new(opcode, payload)
        }
    }

    #[test]
    fn fragmented_message_with_interleaved_ping() {
        let frames = [
            frag(false, OpCode::Text, b"Hel"),
            Frame::new(OpCode::Ping, "p"),
            frag(false, OpCode::Continuation, b"lo, "),
            frag(true, OpCode::Continuation, "wörld".as_bytes()),
            Frame::binary(vec![1, 2]),
        ];
        let msgs: Vec<_> = read_all(&wire(&frames), MessageConfig::default())
            .into_iter()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            msgs,
            vec![
                Message::Ping(b"p".to_vec()),
                Message::Text("Hello, wörld".into()),
                Message::Binary(vec![1, 2]),
            ]
        );
    }

    #[test]
    fn utf8_split_across_fragments_is_fine() {
        let bytes = "é".as_bytes();
        let frames = [
            frag(false, OpCode::Text, &bytes[..1]),
            frag(true, OpCode::Continuation, &bytes[1..]),
        ];
        assert_eq!(
            read_all(&wire(&frames), MessageConfig::default())[0],
            Ok(Message::Text("é".into()))
        );
    }

    fn error_of(frames: &[Frame], cfg: MessageConfig) -> WsError {
        read_all(&wire(frames), cfg).pop().unwrap().unwrap_err()
    }

    #[test]
    fn violations_map_to_close_codes() {
        let d = MessageConfig::default();
        let cases: Vec<(Vec<Frame>, u16)> = vec![
            (vec![frag(true, OpCode::Continuation, b"x")], 1002),
            (
                vec![frag(false, OpCode::Text, b"a"), Frame::text("b")],
                1002,
            ),
            (vec![Frame::new(OpCode::Text, vec![0xC3, 0x28])], 1007),
            // invalid UTF-8 fails fast, before the message is finished
            (vec![frag(false, OpCode::Text, &[0xFF])], 1007),
            // incomplete code point at the end of the message
            (
                vec![
                    frag(false, OpCode::Text, b"a"),
                    frag(true, OpCode::Continuation, &[0xC3]),
                ],
                1007,
            ),
            (vec![Frame::new(OpCode::Close, vec![3])], 1002),
            (
                vec![Frame::new(OpCode::Close, 1005u16.to_be_bytes().to_vec())],
                1002,
            ),
            (
                vec![Frame::new(OpCode::Close, 999u16.to_be_bytes().to_vec())],
                1002,
            ),
            (
                vec![Frame::new(
                    OpCode::Close,
                    [&1000u16.to_be_bytes()[..], &[0xFF]].concat(),
                )],
                1007,
            ),
        ];
        for (frames, code) in cases {
            let e = error_of(&frames, d);
            assert_eq!(e.close_code(), Some(code), "{:?}: {}", frames, e);
        }
        let small = MessageConfig {
            max_message: 4,
            ..d
        };
        let e = error_of(
            &[
                frag(false, OpCode::Binary, b"abc"),
                frag(true, OpCode::Continuation, b"de"),
            ],
            small,
        );
        assert_eq!(e.close_code(), Some(1009));
        let e = error_of(&[Frame::text("hi")], MessageConfig::server());
        assert_eq!(e.close_code(), Some(1002));
    }

    #[test]
    fn close_handling() {
        let close = Message::Close(Some(CloseFrame {
            code: 1000,
            reason: "bye".into(),
        }));
        let mut data = close.encode(None).unwrap();
        data.extend(Frame::text("late").encode().unwrap());
        let got = read_all(&data, MessageConfig::default());
        assert_eq!(got[0], Ok(close));
        assert_eq!(got[1].as_ref().unwrap_err().kind(), WsErrorKind::Closed);
        let empty = Message::Close(None).encode(None).unwrap();
        assert_eq!(
            read_all(&empty, MessageConfig::default())[0],
            Ok(Message::Close(None))
        );
        assert!(
            Message::Close(Some(CloseFrame {
                code: 1006,
                reason: String::new()
            }))
            .encode(None)
            .is_err()
        );
    }

    #[test]
    fn encoding_and_fragmentation() {
        assert_eq!(
            Message::Text("Hello".into()).encode(None).unwrap(),
            [0x81, 5, b'H', b'e', b'l', b'l', b'o']
        );
        assert!(Message::Ping(vec![0; 126]).encode(None).is_err());
        let frames = Message::Binary((0..10).collect()).fragments(4).unwrap();
        assert_eq!(
            frames
                .iter()
                .map(|f| (f.fin, f.opcode, f.payload.len()))
                .collect::<Vec<_>>(),
            vec![
                (false, OpCode::Binary, 4),
                (false, OpCode::Continuation, 4),
                (true, OpCode::Continuation, 2),
            ]
        );
        let empty = Message::Text(String::new()).fragments(4).unwrap();
        assert_eq!(empty.len(), 1);
        assert!(empty[0].fin);
        assert_eq!(Message::Ping(b"x".to_vec()).fragments(0).unwrap().len(), 1);
    }

    #[test]
    fn reading_is_resumable() {
        let msg = Message::Text("a longer message, fragmented and masked".into());
        let data: Vec<u8> = msg
            .fragments(7)
            .unwrap()
            .into_iter()
            .flat_map(|f| f.masked([9, 9, 9, 9]).encode().unwrap())
            .collect();
        for chunk in [1, 2, 5, 13] {
            let mut reader = MessageReader::new(MessageConfig::server());
            let mut bs = ByteStream::with_capacity(chunk + 16);
            let mut got = None;
            for piece in data.chunks(chunk) {
                bs.pull();
                bs.put(piece);
                match reader.read(&mut bs) {
                    Ok(m) => got = Some(m),
                    Err(e) => assert!(e.is_incomplete(), "{}", e),
                }
            }
            assert_eq!(got.as_ref(), Some(&msg), "chunk={}", chunk);
        }
    }

    #[test]
    fn read_from_driver() {
        let data: Vec<u8> = [
            Message::Text("hello, fragmented world".into())
                .fragments(5)
                .unwrap(),
            vec![Frame::new(OpCode::Ping, "p")],
            vec![Frame::binary(vec![1, 2, 3])],
        ]
        .concat()
        .iter()
        .flat_map(|f| f.encode().unwrap())
        .collect();

        let read_all = |input: &[u8]| {
            let mut reader = MessageReader::new(MessageConfig::default());
            let mut bs = ByteStream::with_capacity(8);
            let mut input = input;
            let mut messages = Vec::new();
            loop {
                match reader.read_from(&mut bs, &mut input) {
                    Ok(Some(m)) => messages.push(m),
                    Ok(None) => return Ok(messages),
                    Err(e) => return Err((messages, e)),
                }
            }
        };
        assert_eq!(
            read_all(&data).unwrap(),
            vec![
                Message::Text("hello, fragmented world".into()),
                Message::Ping(b"p".to_vec()),
                Message::Binary(vec![1, 2, 3]),
            ]
        );

        // truncated within a frame, and between the frames of a fragmented message
        let first_fragment = Frame {
            fin: false,
            ..Frame::text("abc")
        }
        .encode()
        .unwrap();
        for input in [&data[..data.len() - 1], &data[..3], &first_fragment] {
            let (_, e) = read_all(input).unwrap_err();
            assert!(matches!(e, ReadError::Truncated(_)), "{}", e);
        }

        // a protocol violation carries its close code
        let (_, e) =
            read_all(&Frame::new(OpCode::Continuation, "x").encode().unwrap()).unwrap_err();
        assert!(
            matches!(&e, ReadError::Parse(e) if e.close_code() == Some(1002)),
            "{}",
            e
        );

        // nothing more after a close message, even if the peer sends more
        let mut closing = Message::Close(None).encode(None).unwrap();
        closing.extend(Frame::text("late").encode().unwrap());
        assert_eq!(read_all(&closing).unwrap(), vec![Message::Close(None)]);
    }
}
