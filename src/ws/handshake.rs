//! Opening handshake ([RFC 6455, section 4](https://www.rfc-editor.org/rfc/rfc6455#section-4)).
//!
//! ```
//! use parsed::http::{Config, parse_request};
//! use parsed::stream::ByteStream;
//! use parsed::ws::handshake;
//!
//! let wire = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\n\
//!     Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
//!     Sec-WebSocket-Version: 13\r\n\r\n";
//! let req = parse_request(&mut ByteStream::borrow(wire), &Config::default()).unwrap();
//! let res = match handshake::accept(&req) {
//!     Ok(res) => res,
//!     Err(e) => e.response(), // 400, or 426 for an unsupported version
//! };
//! assert_eq!(res.status, 101);
//! ```

use crate::http::{Message, Request, Response, Version};
use std::fmt;

const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `Sec-WebSocket-Accept` value for a `Sec-WebSocket-Key`.
pub fn accept_key(key: &[u8]) -> String {
    let mut input = key.to_vec();
    input.extend_from_slice(GUID);
    base64_encode(&sha1(&input))
}

/// Handshake validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeError {
    message: &'static str,
    status: u16,
}

impl HandshakeError {
    fn bad(message: &'static str) -> Self {
        HandshakeError {
            message,
            status: 400,
        }
    }

    /// Status code to reject the request with: 426 (Upgrade Required) for an
    /// unsupported protocol version, 400 otherwise.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Response rejecting the handshake request.
    pub fn response(&self) -> Response {
        let res = match self.status {
            426 => {
                Response::new(426, "Upgrade Required").with_header("Sec-WebSocket-Version", "13")
            }
            _ => Response::new(400, "Bad Request"),
        };
        res.with_body(self.message)
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for HandshakeError {}

/// Validate a client's opening handshake request, returning the key.
pub fn validate_request(req: &Request) -> Result<&[u8], HandshakeError> {
    if req.method != "GET" {
        return Err(HandshakeError::bad("method is not GET"));
    }
    if req.version != Version::Http11 {
        return Err(HandshakeError::bad("protocol version is not HTTP/1.1"));
    }
    if req.header("Host").is_none() {
        return Err(HandshakeError::bad("missing Host header"));
    }
    if !req.has_token("Upgrade", "websocket") {
        return Err(HandshakeError::bad("missing Upgrade: websocket"));
    }
    if !req.has_token("Connection", "Upgrade") {
        return Err(HandshakeError::bad("missing Connection: Upgrade"));
    }
    if req.header("Sec-WebSocket-Version") != Some(b"13") {
        return Err(HandshakeError {
            message: "unsupported Sec-WebSocket-Version",
            status: 426,
        });
    }
    let mut keys = req.headers_named("Sec-WebSocket-Key");
    let key = keys
        .next()
        .ok_or(HandshakeError::bad("missing Sec-WebSocket-Key"))?;
    if keys.next().is_some() || base64_decode(key).map(|k| k.len()) != Some(16) {
        return Err(HandshakeError::bad("invalid Sec-WebSocket-Key"));
    }
    Ok(key)
}

/// Validate a client's opening handshake request, and build the `101 Switching Protocols`
/// response accepting it. Add headers for a selected subprotocol or extensions to the
/// response as needed.
pub fn accept(req: &Request) -> Result<Response, HandshakeError> {
    let key = validate_request(req)?;
    Ok(Response::new(101, "Switching Protocols")
        .with_header("Upgrade", "websocket")
        .with_header("Connection", "Upgrade")
        .with_header("Sec-WebSocket-Accept", accept_key(key)))
}

/// A client's opening handshake request. `key` must be 16 random bytes, fresh for each
/// connection; keep [`request`]'s key header to validate the response with
/// [`validate_response`].
pub fn request(host: &str, target: &str, key: [u8; 16]) -> Request {
    Request::new("GET", target)
        .with_header("Host", host)
        .with_header("Upgrade", "websocket")
        .with_header("Connection", "Upgrade")
        .with_header("Sec-WebSocket-Key", base64_encode(&key))
        .with_header("Sec-WebSocket-Version", "13")
}

/// Validate the server's response to a handshake request sent with the given
/// `Sec-WebSocket-Key` value.
pub fn validate_response(res: &Response, key: &[u8]) -> Result<(), HandshakeError> {
    if res.status != 101 {
        return Err(HandshakeError::bad("status is not 101"));
    }
    if !res.has_token("Upgrade", "websocket") {
        return Err(HandshakeError::bad("missing Upgrade: websocket"));
    }
    if !res.has_token("Connection", "Upgrade") {
        return Err(HandshakeError::bad("missing Connection: Upgrade"));
    }
    if res.header("Sec-WebSocket-Accept") != Some(accept_key(key).as_bytes()) {
        return Err(HandshakeError::bad("invalid Sec-WebSocket-Accept"));
    }
    Ok(())
}

// SHA-1 (RFC 3174): required by the handshake, not used for security.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(BASE64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

// Strict decoding: canonical padding required.
fn base64_decode(text: &[u8]) -> Option<Vec<u8>> {
    if text.len() % 4 != 0 {
        return None;
    }
    let value = |c: u8| BASE64.iter().position(|b| *b == c).map(|v| v as u32);
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (i, chunk) in text.chunks(4).enumerate() {
        let last = i + 1 == text.len() / 4;
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (j, c) in chunk.iter().enumerate() {
            let v = if j >= 4 - pad { 0 } else { value(*c)? };
            n |= v << (18 - 6 * j);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // non-canonical encodings (bits set in the padding) are rejected
        if bytes[3 - pad..].iter().any(|b| *b != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Config, parse_request, parse_response};
    use crate::stream::ByteStream;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(&sha1(&vec![b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn base64_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(plain.as_bytes()), encoded);
            assert_eq!(base64_decode(encoded.as_bytes()).unwrap(), plain.as_bytes());
        }
        for bad in ["Zg", "Zg=", "Z===", "Zh==", "Zg==Zg==", "Z!==", "Zm9v\n"] {
            assert_eq!(base64_decode(bad.as_bytes()), None, "{}", bad);
        }
    }

    #[test]
    fn rfc_example_accept_key() {
        assert_eq!(
            accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn server_side() {
        let good = request("example.com", "/chat", *b"the sample nonce");
        assert_eq!(
            good.header_str("Sec-WebSocket-Key"),
            Some("dGhlIHNhbXBsZSBub25jZQ==")
        );
        let wire = good.encode().unwrap();
        let req = parse_request(&mut ByteStream::borrow(&wire), &Config::default()).unwrap();
        let res = accept(&req).unwrap();
        assert_eq!(res.status, 101);
        assert_eq!(
            res.header_str("Sec-WebSocket-Accept"),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );
        let res_wire = res.encode().unwrap();
        let parsed = parse_response(
            &mut ByteStream::borrow(&res_wire),
            "GET",
            &Config::default(),
        )
        .unwrap();
        assert_eq!(
            validate_response(&parsed, b"dGhlIHNhbXBsZSBub25jZQ=="),
            Ok(())
        );
        assert!(validate_response(&parsed, b"AAAAAAAAAAAAAAAAAAAAAA==").is_err());

        let with = |f: fn(Request) -> Request| accept(&f(good.clone())).unwrap_err();
        assert_eq!(
            with(|r| Request {
                method: "POST".into(),
                ..r
            })
            .status(),
            400
        );
        assert_eq!(
            with(|r| Request {
                version: Version::Http10,
                ..r
            })
            .status(),
            400
        );
        let drop = |name: &'static str| {
            move |mut r: Request| {
                r.headers.retain(|h| h.name != name);
                r
            }
        };
        for name in ["Host", "Upgrade", "Connection", "Sec-WebSocket-Key"] {
            let mut r = good.clone();
            r = drop(name)(r);
            assert_eq!(accept(&r).unwrap_err().status(), 400, "{}", name);
        }
        let mut r = good.clone();
        r.headers.retain(|h| h.name != "Sec-WebSocket-Version");
        let e = accept(&r.with_header("Sec-WebSocket-Version", "8")).unwrap_err();
        assert_eq!(e.status(), 426);
        assert_eq!(e.response().header_str("Sec-WebSocket-Version"), Some("13"));
        let short_key = good.clone().with_header("Sec-WebSocket-Key", "c2hvcnQ=");
        assert!(accept(&short_key).is_err(), "duplicate key");
        let mut r = good.clone();
        r.headers.retain(|h| h.name != "Sec-WebSocket-Key");
        assert!(accept(&r.with_header("Sec-WebSocket-Key", "c2hvcnQ=")).is_err());
        let r = good.with_header("Connection", "keep-alive");
        assert!(accept(&r).is_ok(), "Upgrade token in a list header");
    }
}
