#[macro_use]
extern crate bencher;
use bencher::Bencher;

use parsed::http::{
    BodyDecoder, Config, Framing, RequestParser, parse_request, parse_request_ref,
    parse_response_ref,
};
use parsed::stream::ByteStream;
use parsed::ws::{
    Frame, FrameConfig, FrameParser, Message, MessageConfig, MessageReader, OpCode, parse_frame,
    parse_frame_ref,
};

const UPGRADE: &str = "GET /chat HTTP/1.1\r\nHost: example.com:8000\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-cache\r\nServer: bench\r\nContent-Length: 12\r\n\r\nhello world!";

fn http_request(b: &mut Bencher) {
    let cfg = Config::default();
    b.iter(|| {
        let mut bs = ByteStream::borrow(UPGRADE.as_bytes());
        assert!(parse_request(&mut bs, &cfg).is_ok());
    });
    b.bytes = UPGRADE.len() as u64;
}

fn http_request_zero_copy(b: &mut Bencher) {
    let cfg = Config::default();
    b.iter(|| {
        let (req, _) = parse_request_ref(UPGRADE.as_bytes(), &cfg).unwrap();
        assert_eq!(req.headers.len(), 5);
    });
    b.bytes = UPGRADE.len() as u64;
}

// the same request arriving in 16-byte chunks, parsed with a resumable parser
fn http_request_resumable_16b_chunks(b: &mut Bencher) {
    let mut parser = RequestParser::default();
    b.iter(|| {
        // headroom for bytes left unconsumed by an atomic step (like a CRLF)
        let mut bs = ByteStream::with_capacity(32);
        for chunk in UPGRADE.as_bytes().chunks(16) {
            bs.pull();
            assert_eq!(bs.put(chunk), chunk.len());
            match parser.parse(&mut bs) {
                Ok(_) => return,
                Err(e) => assert!(e.is_incomplete()),
            }
        }
        panic!("request not parsed");
    });
    b.bytes = UPGRADE.len() as u64;
}

fn chunked_request() -> String {
    let mut text =
        "POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_string();
    for _ in 0..16 {
        text.push_str(&format!("400\r\n{}\r\n", "x".repeat(0x400)));
    }
    text.push_str("0\r\n\r\n");
    text
}

fn http_request_chunked_body(b: &mut Bencher) {
    let text = chunked_request();
    let cfg = Config::default();
    b.iter(|| {
        let req = parse_request(&mut ByteStream::borrow(text.as_bytes()), &cfg).unwrap();
        assert_eq!(req.body.len(), 16 << 10);
    });
    b.bytes = text.len() as u64;
}

// streaming decoding: pieces are borrowed from the buffer, nothing is accumulated
fn http_body_decoder_chunked(b: &mut Bencher) {
    let text = chunked_request();
    let body = &text.as_bytes()[text.find("\r\n\r\n").unwrap() + 4..];
    let cfg = Config::default();
    b.iter(|| {
        let mut decoder = BodyDecoder::new(Framing::Chunked, &cfg);
        let mut bs = ByteStream::borrow(body);
        let mut total = 0;
        while let Some(piece) = decoder.decode(&mut bs).unwrap() {
            total += piece.len();
        }
        assert_eq!(total, 16 << 10);
    });
    b.bytes = body.len() as u64;
}

fn http_response_zero_copy(b: &mut Bencher) {
    let cfg = Config::default();
    b.iter(|| {
        let (res, _) = parse_response_ref(RESPONSE.as_bytes(), "GET", false, &cfg).unwrap();
        assert_eq!(res.body.len(), 12);
    });
    b.bytes = RESPONSE.len() as u64;
}

fn ws_frame(b: &mut Bencher) {
    let bytes: Vec<u8> = vec![129, 134, 87, 35, 230, 82, 63, 70, 138, 62, 56, 2];
    let cfg = FrameConfig::default();
    b.iter(|| {
        let mut bs = ByteStream::borrow(&bytes);
        assert!(parse_frame(&mut bs, &cfg).is_ok());
    });
    b.bytes = bytes.len() as u64;
}

fn frame_64k() -> Vec<u8> {
    Frame::new(OpCode::Binary, vec![42u8; 65536])
        .masked([1, 2, 3, 4])
        .encode()
        .unwrap()
}

fn ws_frame_64k(b: &mut Bencher) {
    let bytes = frame_64k();
    let cfg = FrameConfig::default();
    b.iter(|| {
        let mut bs = ByteStream::borrow(&bytes);
        assert!(parse_frame(&mut bs, &cfg).is_ok());
    });
    b.bytes = bytes.len() as u64;
}

fn ws_frame_64k_zero_copy(b: &mut Bencher) {
    let bytes = frame_64k();
    let cfg = FrameConfig::default();
    b.iter(|| {
        let (frame, _) = parse_frame_ref(&bytes, &cfg).unwrap();
        assert_eq!(frame.payload.len(), 65536);
    });
    b.bytes = bytes.len() as u64;
}

// a 64 KiB frame received in 4 KiB chunks
fn ws_frame_64k_resumable_4k_chunks(b: &mut Bencher) {
    let bytes = frame_64k();
    let mut parser = FrameParser::default();
    b.iter(|| {
        let mut bs = ByteStream::with_capacity(4096 + 16);
        for chunk in bytes.chunks(4096) {
            bs.pull();
            assert_eq!(bs.put(chunk), chunk.len());
            match parser.parse(&mut bs) {
                Ok(_) => return,
                Err(e) => assert!(e.is_incomplete()),
            }
        }
        panic!("frame not parsed");
    });
    b.bytes = bytes.len() as u64;
}

// a 64 KiB text message in 16 masked fragments: reassembly, unmasking, UTF-8 validation
fn ws_message_64k_fragmented(b: &mut Bencher) {
    let bytes: Vec<u8> = Message::Text("x".repeat(65536))
        .fragments(4096)
        .unwrap()
        .into_iter()
        .flat_map(|f| f.masked([1, 2, 3, 4]).encode().unwrap())
        .collect();
    b.iter(|| {
        let mut reader = MessageReader::new(MessageConfig::server());
        let mut bs = ByteStream::borrow(&bytes);
        assert!(matches!(reader.read(&mut bs), Ok(Message::Text(t)) if t.len() == 65536));
    });
    b.bytes = bytes.len() as u64;
}

benchmark_group!(
    http,
    http_request,
    http_request_zero_copy,
    http_request_resumable_16b_chunks,
    http_request_chunked_body,
    http_body_decoder_chunked,
    http_response_zero_copy,
    ws_frame,
    ws_frame_64k,
    ws_frame_64k_zero_copy,
    ws_frame_64k_resumable_4k_chunks,
    ws_message_64k_fragmented
);
benchmark_main!(http);
