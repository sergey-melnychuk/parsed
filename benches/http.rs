#[macro_use]
extern crate bencher;
use bencher::Bencher;

use parsed::stream::ByteStream;
use parsed::http::parse_http_request;
use parsed::ws::parse_frame;

fn http_request(b: &mut Bencher) {
    let text = "GET /chat HTTP/1.1\r\nHost: example.com:8000\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    b.iter(|| {
        let mut bs: ByteStream = text.to_string().into();
        let req = parse_http_request(&mut bs);
        assert!(req.is_some());
    });
}

fn ws_frame(b: &mut Bencher) {
    let bytes: Vec<u8> = vec![129, 134, 87, 35, 230, 82, 63, 70, 138, 62, 56, 2];
    b.iter(|| {
        let mut bs = ByteStream::wrap(bytes.clone());
        let opt = parse_frame(&mut bs);
        assert!(opt.is_some());
    });
}



benchmark_group!(http, http_request, ws_frame);
benchmark_main!(http);
