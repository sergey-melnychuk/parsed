#[macro_use]
extern crate bencher;
use bencher::Bencher;

use parsed::stream::ByteStream;
use parsed::http::parse_http_request;

fn bench_parse_http_request(b: &mut Bencher) {
    let text = "GET /chat HTTP/1.1\r\nHost: example.com:8000\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    b.iter(|| {
        let mut bs: ByteStream = text.to_string().into();
        let req = parse_http_request(&mut bs);
        assert!(req.is_some());
    });
}

benchmark_group!(http, bench_parse_http_request);
benchmark_main!(http);
