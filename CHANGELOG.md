# Changelog

## 0.4.0 (2026-09-28)

A rewrite for parsing custom protocols from streams: parsers resume where the input ran
out instead of starting over, read borrowed input without copying, and cover the usual
building blocks of wire formats (choice, delimited and length-prefixed framing,
varints, decimal numbers, recursion). Nearly every public API changed; see
[Migrating from 0.3](#migrating-from-03).

### Resumable parsing

- `Matcher` has an associated `State` and a `resume` method. When input runs out, the
  results of completed steps are kept and parsing continues at the step that ran out of
  input, so messages may be larger than the buffer. `Matcher::do_match` /
  `Applicator::apply` are one-shot: they restart from scratch, and a failed match
  consumes nothing.
- `matcher::Resumable` drives a matcher over incremental input, and
  `Resumable::read_from(&mut stream, &mut impl Read)` is the whole loop: `Ok(None)` when
  the input ends cleanly between values, `ReadError::Truncated` when it ends in the
  middle of one, progress kept across `WouldBlock` (for non-blocking sockets).
- Results don't depend on how the input is split into chunks. So `repeat`, `maybe`,
  `or` and `separated` commit to an item once it has consumed input; wrap it in
  `attempt` to backtrack further.
- Streams are *open* (more input may follow: `with_capacity`, `growable`, `partial`) or
  *closed* (`wrap`, `borrow`, `From`, `close()`). At the end of an open stream,
  variable-length matchers report `Incomplete`.
- A full buffer no longer hangs: `Incomplete` on a stream that is full, with nothing
  that `pull()` could drop, is `ErrorKind::TooLarge` ("input does not fit into the
  buffer").
- Parsers are `Send` (boxed matchers `Send + Sync`), so they can be moved between
  threads and held across `.await`. Matcher states must be `Send`, and so must values
  that combinators hold in their state (e.g. the first value of `then`).

### Streams and zero-copy reading

- `ByteStream<'a>` owns a buffer or borrows a slice without copying it:
  `ByteStream::borrow` (complete input) and `ByteStream::partial` (input so far).
- `ByteStream::growable(initial, max)`, `put_some`, `read_from(&mut impl Read)` (reads
  straight into the buffer, closes the stream at the end of input), `get_array`,
  `take`, `skip`, `peek`, `remaining`, `is_empty`, `is_full`, `close`, `is_closed`.
- `ByteStream::offset()` counts from the start of the stream and doesn't change on
  `pull()`. Error offsets and spans use it; `ByteStream::slice(range)` returns the bytes
  of a span.
- Zero-copy matchers `skip_while`, `skip_while1`, `skip_until`, `advance` and `tag`
  consume without copying; `recognize` and `spanned` produce the range of offsets that
  was matched.

### Combinators

- Choice: `Matcher::or`, with merged error messages ("expected '+' or '-' or ':'").
- Sequencing: `Matcher::then_ignore`, `ignore_then`, `ignore`, `try_map`,
  `try_map_with`, `context`; free functions `preceded`, `terminated`, `delimited`.
- Repetition: `separated`, `repeat_until`; `times(0, p)` now matches nothing, and
  `repeat` of a matcher that consumes nothing no longer loops forever.
- Bytes: `take_while` (formerly `until`, which is deprecated), `take_while1`, `tag`,
  `take_until` (multi-byte patterns, also split across chunks), `rest`; `exact` and
  `string` accept non-`'static` input.
- Numbers: little-endian `get_u16_le`, `get_u32_le`, `get_u64_le`; `varint` (LEB128);
  `decimal`, `integer`.
- Framing: `sized(n, inner)` (the inner matcher sees exactly `n` bytes as its whole
  input and must consume them), `length_prefixed`, and `limit`, which fails with
  `ErrorKind::TooLarge` and hides everything beyond the limit from the inner matcher,
  so it bounds the work done as well as the memory.
- Lookahead: `peek`, `not`, `eof`. Recursion: `lazy` (the recursive matcher is built
  once). Other: `attempt`, `fail`, `Either`.

### Errors

- `MatchError` has a kind (`ErrorKind::Unexpected`, `Incomplete`, `TooLarge`), an
  offset, and an optional context (`Matcher::context`). Its message is built only when
  displayed, and the alternatives of `or` merge inline when they are single bytes, so
  common failed alternatives don't allocate.
- Constructors: `unexpected`, `unexpected_byte`, `invalid`, `incomplete`, `too_large`.
- Mismatch errors report the byte actually found.

### HTTP (`http` feature)

- Requests and responses: owned `Request` / `Response`, and zero-copy `RequestRef` /
  `ResponseRef` borrowing from the input. Header access (`header`, `header_str`,
  `headers_named`, `has_token`, `keep_alive`) is shared through the `Message` trait.
- Parsers: `RequestParser` / `ResponseParser` (resumable, whole messages, with
  `read_from`), `RequestHeadParser` / `ResponseHeadParser` followed by a `BodyDecoder`
  that yields the body in pieces borrowed from the buffer, one-shot `parse_request` /
  `parse_response`, and zero-copy `parse_request_ref` / `parse_response_ref`.
- Bodies: `Content-Length`, chunked (extensions and trailers accepted), and read until
  close for responses, following the RFC 9112 rules (HEAD, 1xx, 204, 304, CONNECT).
- Strict validation against request smuggling: token and field characters, request
  target, HTTP/1.0 and 1.1 only, no obsolete line folding or bare LF, `Host` rules, and
  no ambiguous framing (`Transfer-Encoding` with `Content-Length`, conflicting
  `Content-Length` values, `chunked` not last, unknown transfer codings in requests).
- Limits (`Config`): head size, header count, body size, trailer size, chunk line length.
  `error_status` maps a parse error to 400, 413 or 431.
- Encoding validates the start line and headers, so header injection isn't possible;
  `with_body` sets `Content-Length`; `encode_chunk` / `encode_last_chunk` write chunked
  bodies.

### WebSocket (`ws` feature, implies `http`)

- Frames: `Frame` with `OpCode`, `Frame::masked` / `unmask`, word-at-a-time
  `apply_mask`, validated `encode`. `FrameParser` (resumable, with `read_from`),
  `parse_frame`, and zero-copy `parse_frame_ref`. `FrameConfig` sets the payload limit,
  masking rule (`FrameConfig::server()` / `client()`) and allowed reserved bits.
  Reserved opcodes, fragmented or oversized control frames, and non-minimal lengths are
  rejected.
- Messages: `MessageReader` reassembles fragmented messages, delivers control frames as
  they arrive (also between fragments), validates UTF-8 (failing fast across fragments),
  close codes and message size, and has `read_from`. `WsError::close_code` gives the code
  to fail the connection with. `Message::encode` and `Message::fragments` for sending.
- Handshake (`ws::handshake`): `accept` validates a client's request and builds the 101
  response (rejections via `HandshakeError::response`, with 426 for an unsupported
  version); `request` and `validate_response` for clients; `accept_key`. No dependencies:
  SHA-1 and base64 are implemented locally.
- Fixed from 0.3: frames with 16-bit and 64-bit lengths panicked, frames over 64 KiB and
  masks were encoded incorrectly, and a huge declared length allocated up-front.

### Examples and tests

- `examples/resp/`: a small Redis-compatible server, with the RESP2 grammar in
  `grammar.rs` and the server loop in `server.rs`. Run `cargo run --example resp`, then
  `redis-cli -p 6380`.
- Interoperability with independent implementations, in-process over real TCP
  connections, in both directions: HTTP with ureq and tiny_http, RESP with an embedded
  mini-redis and the `redis` crate (against the example's server), WebSocket with
  tungstenite.
- Property tests check chunk invariance for the combinators and the protocol parsers;
  four fuzz targets (`http_request`, `http_response`, `ws_frame`, `ws_message`) also
  check agreement between the owned and zero-copy parsers.

### Performance

- One-shot HTTP request parsing is about 5x faster than 0.3 (748 ns vs 3,997 ns in the
  bundled benchmark), about 8x zero-copy (503 ns); WebSocket frames about 3x (61 ns vs
  206 ns). That's despite the stricter validation.
- `benches/core.rs` covers custom-protocol workloads: CRLF-delimited lines, number lists,
  length-prefixed records and RESP commands. Multi-byte pattern search scans a word at a
  time.

### Other

- Fixed: `ByteStream::put_u16` / `put_u32` / `put_u64` returned `false` on success.
- Edition 2024, minimum Rust version 1.85, no dependencies, `#![forbid(unsafe_code)]`,
  rustdoc for all public items. `Cargo.lock` is no longer ignored.
- CI runs fmt, clippy and tests for each feature set, docs, benches, builds the examples,
  builds on the minimum Rust version, and fuzzes.

### Migrating from 0.3

Core:

- Custom `Matcher` implementations implement `resume(&self, &mut State, &mut ByteStream)`
  with `type State` instead of `do_match`; `do_match` is provided. Closures
  `|bs: &mut ByteStream| -> Result<T, MatchError>` are matchers as before.
- `ByteStream` has a lifetime parameter (`ByteStream<'static>` for owned buffers).
  `wrap` creates a *closed* stream and `with_capacity` an *open* one: at the end of an
  open stream, `repeat`, `maybe` and `take_while` report `Incomplete` instead of
  finishing.
- `until` → `take_while` (the old name still works, deprecated).
- `Matcher::boxed` returns `Boxed<T>` instead of `Box<dyn Matcher<T>>`; the matcher must
  be `Send + Sync`.
- `MatchError::over_capacity(offset, available, requested)` →
  `MatchError::incomplete(offset, requested, available)`;
  `MatchError::unexpected(offset, got: String, expected: String)` →
  `MatchError::unexpected(offset, found: Option<u8>, expected)`. Use `kind()` /
  `is_incomplete()` to tell whether more input can help.
- A failed match no longer consumes input, and `single` / `one` no longer consume the
  mismatched byte.

HTTP (`http` feature):

- `parse_http_request(&mut bs) -> Option<Request>` →
  `parse_request(&mut bs, &Config::default()) -> Result<Request, MatchError>`.
- `Request { method, path, protocol, headers, content }` →
  `Request { method, target, version: Version, headers, body }`.
- `Response { protocol, code, message, headers, content }` →
  `Response { version, status, reason, headers, body }`; `Into<String>` →
  `encode() -> Result<Vec<u8>, EncodeError>`; `Response::new(status, reason)` with
  `with_header` / `with_body`.
- `Header::value` is `Vec<u8>` (values may contain non-UTF-8 bytes): use
  `Message::header_str`, which is also case-insensitive.
- `as_string` is removed.

WebSocket (now the `ws` feature):

- `parse_frame(&mut bs) -> Option<Frame>` →
  `parse_frame(&mut bs, &FrameConfig::default()) -> Result<Frame, MatchError>`.
- `Frame { fin, opcode: u8, len, mask, body }` →
  `Frame { fin, rsv, opcode: OpCode, mask, payload }`; `Into<Vec<u8>>` →
  `encode() -> Result<Vec<u8>, WsError>`.
- `decode_frame_body(&body, &mask)` → `Frame::unmask()` or `apply_mask(&mut payload, key)`.
- For whole messages, use `MessageReader` instead of assembling frames by hand.

## 0.3.0

- HTTP and WebSocket parsers moved behind the `http` feature.
- Throughput reporting for benchmarks.
- `times` combinator.
