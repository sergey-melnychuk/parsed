![](https://github.com/sergey-melnychuk/parsed/workflows/Rust/badge.svg)

# Parsed: parser combinators library in Rust

Resumable, zero-copy parser combinators over a byte buffer, for custom protocols, text or
binary. No dependencies, no `unsafe`.

```rust
use parsed::parser::{before, single, unit, Applicator, Matcher, ParserExt};
use parsed::stream::ByteStream;

#[derive(Default)]
struct KeyValue {
    key: String,
    value: String,
}

let kv = unit(KeyValue::default)
    .then(before('='))
    .save(|kv, bytes| kv.key = String::from_utf8(bytes).unwrap())
    .then(single('='))
    .skip()
    .then(before(';'))
    .save(|kv, bytes| kv.value = String::from_utf8(bytes).unwrap());

let mut bs: ByteStream = "answer=42;".to_string().into();
let parsed = bs.apply(kv).unwrap();
assert_eq!(parsed.key, "answer");
assert_eq!(parsed.value, "42");
```

## Combinators

- sequence: `then`, `then_ignore`, `ignore_then`, `preceded`, `terminated`, `delimited`,
  `then_with` (the next matcher depends on a value, e.g. a length);
- choice and repetition: `or`, `maybe`, `repeat`, `repeat_until`, `times`, `separated`,
  `attempt` (full backtracking);
- bytes: `one`, `single`, `tag`, `exact`, `bytes`, `take_while`, `take_while1`,
  `take_until`, `before`, `rest`, and the zero-copy `skip_while`, `skip_until`,
  `advance` with `recognize` / `spanned`;
- numbers: `get_u8` and big/little-endian `get_u16` ... `get_u64` (`_le`), `varint`
  (LEB128), `decimal`, `integer`;
- framing: `sized` (the inner matcher sees exactly N bytes), `length_prefixed`, `limit`;
- lookahead: `peek`, `not`, `eof`; recursion: `lazy`; errors: `try_map`,
  `try_map_with`, `context`, `fail`.

[`examples/resp/`](examples/resp) is a small Redis-compatible server: the RESP2 grammar
(text lines, integers, length-prefixed binary strings, arrays nested recursively up to a
depth limit) in [`grammar.rs`](examples/resp/grammar.rs), and a server loop on
`Resumable::read_from` in [`server.rs`](examples/resp/server.rs). Try it with
`cargo run --example resp` and `redis-cli -p 6380`.

## Streaming

Matchers are built for input that arrives in pieces:

- Errors tell whether more input may help: `MatchError::is_incomplete()` (kind
  `ErrorKind::Incomplete`) means the input ended too early, while `ErrorKind::Unexpected`
  means it is invalid.
- A `ByteStream` is either *open* (`ByteStream::with_capacity`, more bytes may be `put`)
  or *closed* (`ByteStream::wrap`, `From<String>`, or after `close()`). At the end of an
  open stream, variable-length matchers like `repeat` or `take_while` can't know whether
  they are done, so they report `Incomplete`.
- **One-shot parsing** (`stream.apply(matcher)`, `Matcher::do_match`) never consumes
  input on failure: after `Incomplete`, put more bytes and apply the matcher again. It
  restarts from scratch, so the whole message must fit into the buffer.
- **Resumable parsing** (`matcher::Resumable`, `http::RequestParser`, `ws::FrameParser`)
  keeps the results of completed steps on `Incomplete`, and the next call continues at the
  step that ran out of input. Consumed bytes can be dropped with `ByteStream::pull()`, so
  messages may be larger than the buffer. Use `limit(max, matcher)` to bound memory.
- Buffers: `ByteStream::with_capacity` (fixed) or `ByteStream::growable(initial, max)`;
  `read_from(&mut impl Read)` reads straight into the buffer. Steps that match all or
  nothing (like `tag`, or a whole one-shot match) need their input buffered at once: if
  the buffer is full and such a step still needs more, the result is a `TooLarge` error
  ("input does not fit into the buffer"), never a silent hang.

`Resumable::read_from(&mut stream, &mut reader)` is the whole loop: it parses the next
value, reading from any `std::io::Read` as needed, returns `None` when the input ends
cleanly between values, and reports input that ends in the middle of a value as
`ReadError::Truncated`. A `WouldBlock` read keeps the progress, so it works with
non-blocking sockets too.

```rust
use parsed::matcher::Resumable;
use parsed::parser::{tag, take_until, Matcher};
use parsed::stream::ByteStream;

let mut lines = Resumable::new(take_until(b"\r\n").then_ignore(tag(b"\r\n")));
let mut socket = &b"PING\r\nPING\r\n"[..]; // any `impl Read`
let mut bs = ByteStream::growable(1024, 64 << 10);
while let Some(line) = lines.read_from(&mut bs, &mut socket).unwrap() {
    assert_eq!(line, b"PING");
}
```

Results don't depend on how the input is split into chunks. Because of that, `repeat` and
`maybe` only backtrack over an item that failed *without consuming input*. Wrap an item in
`attempt(...)` to backtrack over it fully (it then restarts on `Incomplete`).

```rust
use parsed::matcher::Resumable;
use parsed::parser::{before, tag, Matcher};
use parsed::stream::ByteStream;

let mut line = Resumable::new(before('\n').then(tag(b"\n")).map(|(line, _)| line));
let mut bs = ByteStream::with_capacity(8);

bs.put(b"a long ");
assert!(line.parse(&mut bs).unwrap_err().is_incomplete());
bs.pull(); // the partial line lives in the parser state now

bs.put(b"line\n");
assert_eq!(line.parse(&mut bs).unwrap(), b"a long line");
```

## Zero-copy

`ByteStream::borrow(&[u8])` (complete input) and `ByteStream::partial(&[u8])` (received
so far, more may follow) read a slice without copying it. `skip_while`, `advance` and
`tag` match without copying, and `recognize(matcher)` produces the range of stream offsets
that was matched: slice the input with it, or use `ByteStream::slice`. Offsets count from
the start of the stream, so they stay valid across `pull()`.

```rust
use parsed::parser::{recognize, skip_while1, tag, Applicator, Matcher};
use parsed::stream::ByteStream;

let input = b"key=value";
let kv = recognize(skip_while1(|b| b != b'=', "key"))
    .then(tag(b"="))
    .then(recognize(skip_while1(|b| b != b';', "value")))
    .map(|((key, _), value)| (key, value));
let (key, value) = ByteStream::borrow(input).apply(kv).unwrap();
assert_eq!((&input[key], &input[value]), (&b"key"[..], &b"value"[..]));
```

## Features

Two optional protocol implementations, built on the combinators:

- `http`: HTTP/1.x requests and responses, parsed whole (resumable, or zero-copy from a
  slice), or as a head followed by a streaming `BodyDecoder`. `Content-Length`, chunked
  and read-until-close bodies are supported. Validation is strict to prevent request
  smuggling, sizes are bounded by `http::Config`, and `http::error_status` maps a parse
  error to 400/413/431. Requests and responses are validated when encoded, so header
  injection isn't possible.
- `ws` (implies `http`): WebSocket frames (resumable or zero-copy), `ws::MessageReader`
  for whole messages (fragments reassembled, control frames interleaved, UTF-8 and close
  codes validated, errors mapped to close codes), message encoding and fragmentation,
  and the opening handshake (`ws::handshake`).

## Development

```sh
cargo test --all-features
cargo bench --all-features
cargo run --example resp   # a Redis-compatible server on 127.0.0.1:6380
```

Besides unit and property tests, `tests/` checks interoperability with independent
implementations, in-process over TCP: HTTP with ureq and tiny_http, RESP with
mini-redis and the `redis` crate, WebSocket with tungstenite.

```sh
cargo +nightly fuzz run http_request   # or http_response, ws_frame, ws_message; needs cargo-fuzz
```

Minimum supported Rust version: 1.85.
