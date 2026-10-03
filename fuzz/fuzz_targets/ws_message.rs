#![no_main]

use libfuzzer_sys::fuzz_target;
use parsed::stream::ByteStream;
use parsed::ws::{Message, MessageConfig, MessageReader, WsError};

// Reading messages from the same input, all at once or in small pieces, gives the same
// messages and the same final error.
fuzz_target!(|data: &[u8]| {
    let Some((&chunk, input)) = data.split_first() else {
        return;
    };
    let cfg = MessageConfig {
        max_message: 1 << 16,
        ..MessageConfig::default()
    };
    let whole = read_all(input, input.len().max(1), cfg);
    let pieces = read_all(input, chunk as usize % 32 + 1, cfg);
    assert_eq!(whole, pieces);
});

fn read_all(input: &[u8], chunk: usize, cfg: MessageConfig) -> (Vec<Message>, Option<WsError>) {
    let mut reader = MessageReader::new(cfg);
    let mut bs = ByteStream::with_capacity(chunk + 16);
    let mut messages = Vec::new();
    for piece in input.chunks(chunk) {
        bs.pull();
        assert_eq!(bs.put(piece), piece.len());
        loop {
            match reader.read(&mut bs) {
                Ok(m) => messages.push(m),
                Err(e) if e.is_incomplete() => break,
                Err(e) => return (messages, Some(e)),
            }
        }
    }
    (messages, None)
}
