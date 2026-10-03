//! Test helpers.

use crate::matcher::{MatchError, Matcher, Resumable};
use crate::stream::ByteStream;

/// Open stream holding `data`.
pub fn open(data: &[u8]) -> ByteStream<'_> {
    ByteStream::partial(data)
}

/// Feed `data` to a resumable matcher `chunk` bytes at a time through a small buffer,
/// dropping consumed bytes before each put; `close` the stream after the last chunk.
pub fn feed<T, M: Matcher<T>>(
    m: M,
    data: &[u8],
    chunk: usize,
    close: bool,
) -> Result<T, MatchError> {
    let chunk = chunk.max(1);
    let mut parser = Resumable::new(m);
    let mut bs = ByteStream::with_capacity(chunk.max(16));
    let mut rest = data;
    loop {
        bs.pull();
        let n = chunk.min(rest.len()).min(bs.cap());
        bs.put(&rest[..n]);
        rest = &rest[n..];
        if rest.is_empty() && close {
            bs.close();
        }
        let result = parser.parse(&mut bs);
        match &result {
            Err(e) if e.is_incomplete() && !rest.is_empty() && n > 0 => continue,
            _ => return result,
        }
    }
}
