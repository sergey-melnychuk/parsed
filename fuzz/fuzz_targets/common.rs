use parsed::matcher::{MatchError, Matcher, Resumable};
use parsed::stream::ByteStream;

/// Checks that a failed one-shot parse consumes nothing, and that resumable parsing of
/// the same input in `chunk`-sized pieces through a small buffer gives the same result.
/// Returns the input and the one-shot result, for further checks.
pub fn check<T, M, F>(matcher: F, data: &[u8]) -> Option<(&[u8], Result<T, MatchError>)>
where
    T: PartialEq + std::fmt::Debug,
    M: Matcher<T>,
    F: Fn() -> M,
{
    let (&chunk, input) = data.split_first()?;
    let mut bs = ByteStream::borrow(input);
    let whole = matcher().do_match(&mut bs);
    if whole.is_err() {
        assert_eq!(bs.pos(), 0, "failed parse consumed input");
    }
    let fed = feed(matcher(), input, chunk as usize % 64 + 1);
    match (&whole, &fed) {
        (Ok(a), Ok(b)) => assert_eq!(a, b),
        (Err(a), Err(b)) => assert_eq!(a.kind(), b.kind(), "{} vs {}", a, b),
        _ => panic!("one-shot {:?} vs resumable {:?}", whole, fed),
    }
    Some((input, whole))
}

fn feed<T, M: Matcher<T>>(m: M, data: &[u8], chunk: usize) -> Result<T, MatchError> {
    let mut parser = Resumable::new(m);
    let mut bs = ByteStream::with_capacity(chunk + 16);
    let mut rest = data;
    loop {
        bs.pull();
        let n = chunk.min(rest.len()).min(bs.cap());
        bs.put(&rest[..n]);
        rest = &rest[n..];
        if rest.is_empty() {
            bs.close();
        }
        let result = parser.parse(&mut bs);
        match &result {
            Err(e) if e.is_incomplete() && !rest.is_empty() && n > 0 => continue,
            _ => return result,
        }
    }
}
