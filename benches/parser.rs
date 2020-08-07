#![feature(test)]
#[cfg(test)]

use parsed::stream::ToStream;
use parsed::http::parse_http_request;

extern crate test;
use test::Bencher;

// rustup install nightly
// rustup run nightly cargo bench

#[bench]
fn bench_parse_http_request(b: &mut Bencher) {
    let text = "GET /chat HTTP/1.1\r\nHost: example.com:8000\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    b.iter(|| {
        let mut bs = text.to_string().into_stream();
        let req = parse_http_request(&mut bs);
        assert!(req.is_some());
    });
}
