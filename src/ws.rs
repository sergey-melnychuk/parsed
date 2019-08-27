/*
https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers

GET /chat HTTP/1.1
Host: example.com:8000
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

Response['Sec-WebSocket-Accept'] = base64(sha1( Request['Sec-WebSocket-Key'] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ))
*/

use crate::parser::{Parser, bytes, Applicator};
use crate::stream::ByteStream;

#[derive(Debug)]
struct Frame {
    fin: bool,
    opcode: u8,
    len: u32,
    mask: Option<[u8; 4]>,
    body: Vec<u8>,
}

fn frame_opts() -> Parser<FrameOpts> {
    Parser::init(|| ())
        .then(bytes(2))
        .map(|(_, word)| FrameOpts::new(word))
}

fn parse_frame(stream: &mut ByteStream) -> Option<Frame> {
    let opts = stream.apply(frame_opts()).unwrap();
    let (fin, code, mask) = (opts.fin, opts.code, opts.mask);

    let p0 = Parser::init(|| ());
    let p1 = match opts.len {
        127 => p0.then(bytes(8))
                .map(|(_, vec)| build_u64(vec) as u32),
        126 => p0.then(bytes(2))
                .map(|(_, vec)| build_u16(vec) as u32),
        n => p0.map(move |_| n as u32)
    };

    let p2 = p1.map( move |len| Frame {
        fin,
        opcode: code,
        mask: None,
        body: Vec::with_capacity(len as usize),
        len,
    });

    let p3 = if mask {
        p2.then(bytes(4))
         .save(|frame, vec| {
             let mask: [u8; 4] = [vec[0], vec[1], vec[2], vec[3]];
             frame.mask = Some(mask);
         })
    } else {
        p2
    };

    let p4 = p3.then_with(|frame| bytes(frame.len as usize))
        .save(|frame, vec| frame.body = vec);

    stream.apply(p4)
        .map(|x| Some(x))
        .unwrap_or_else(|_| None)
}

fn build_u16(vec: Vec<u8>) -> u16 {
    vec.into_iter().fold(0 as u16, |acc, b| acc << 8 + b)
}

fn build_u64(vec: Vec<u8>) -> u64 {
    vec.into_iter().fold(0 as u64, |acc, b| acc << 8 + b)
}

#[derive(Default)]
struct FrameOpts {
    fin: bool,
    code: u8,
    len: u8,
    mask: bool,
}

impl FrameOpts {
    fn new(word: Vec<u8>) -> FrameOpts {
        FrameOpts {
            fin: (word[0] >> 7) > 0,
            code: (127 as u8) & word[0],
            len: (127 as u8) & word[1],
            mask: (word[1] >> 7) > 0,
        }
    }

}

struct FrameBuilder {
    fin_op: u8,
    mask_len: u8,
    len2: u16,
    len8: u64,
    len: u32,
    mask: [u8; 4],
    body: Vec<u8>,
}

impl FrameBuilder {
    fn build(self) -> Frame {
        let len = (127 as u8) | self.mask_len;
        Frame {
            fin: (self.fin_op >> 7) > 0,
            opcode: (127 as u8) | self.fin_op,
            len: if len <= 125 {len as u32} else {if len == 126 {self.len2 as u32} else {self.len8 as u32}},
            mask: if (self.mask_len >> 7) > 0 {Some(self.mask)} else {None},
            body: self.body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::ByteStream;

    #[test]
    fn opts() {
        let bytes: Vec<u8> = vec![128 + 32, 128 + 3];
        let mut stream = ByteStream::wrap(bytes);
        let opts = stream.apply(frame_opts()).unwrap();
        assert_eq!(opts.fin, true);
        assert_eq!(opts.code, 32);
        assert_eq!(opts.mask, true);
        assert_eq!(opts.len, 3);
    }

    #[test]
    fn frame1() {
        let bytes: Vec<u8> = vec![128 + 32, 128 + 7, 1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16];
        let mut stream = ByteStream::wrap(bytes);
        let opt = parse_frame(&mut stream);
        assert!(opt.is_some());
        let frame = opt.unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, 32);
        assert_eq!(frame.len, 7);
        assert_eq!(frame.mask, Some([1, 2, 3, 4]));
        assert_eq!(frame.body, vec![10, 11, 12, 13, 14, 15, 16]);
    }

    #[test]
    fn frame2() {
        let bytes: Vec<u8> = vec![31, 3, 10, 20, 30];
        let mut stream = ByteStream::wrap(bytes);
        let opt = parse_frame(&mut stream);
        assert!(opt.is_some());
        let frame = opt.unwrap();
        assert!(!frame.fin);
        assert_eq!(frame.opcode, 31);
        assert_eq!(frame.len, 3);
        assert_eq!(frame.mask, None);
        assert_eq!(frame.body, vec![10, 20, 30]);
    }

}