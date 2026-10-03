//! Primitive matchers and combinators.
//!
//! Primitives come in two flavours:
//!
//! - *atomic* ones ([`one`], [`single`], [`exact`], [`get_u16`], ...) either match
//!   completely or consume nothing; on `Incomplete` they are retried from scratch;
//! - *accumulating* ones ([`take_while`], [`bytes`]) consume whatever is available and
//!   keep it in their state, so their output may be larger than the buffer.
//!
//! Combinators taking a variable number of items ([`repeat`], [`maybe`]) only backtrack
//! over an item that failed without consuming input; an item that consumed input and
//! then failed is an error (use [`attempt`] to backtrack further). This keeps results
//! independent of how the input is split into chunks.

use crate::matcher::StartState;
pub use crate::matcher::{ErrorKind, MatchError, Matcher, Resumable, unit};
use crate::stream::ByteStream;
use std::marker::PhantomData;
use std::mem;
use std::ops::Range;

/// Matcher returned by [`ParserExt::save`].
pub struct Save<M, T, U, F> {
    matcher: M,
    func: F,
    phantom: PhantomData<fn() -> (T, U)>,
}

impl<M, T, U, F> Matcher<T> for Save<M, T, U, F>
where
    M: Matcher<(T, U)>,
    F: Fn(&mut T, U),
{
    type State = M::State;

    fn resume(&self, state: &mut M::State, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        let (mut t, u) = self.matcher.resume(state, bs)?;
        (self.func)(&mut t, u);
        Ok(t)
    }
}

/// Matcher returned by [`ParserExt::skip`].
pub struct Skip<M, T, U> {
    matcher: M,
    phantom: PhantomData<fn() -> (T, U)>,
}

impl<M, T, U> Matcher<T> for Skip<M, T, U>
where
    M: Matcher<(T, U)>,
{
    type State = M::State;

    fn resume(&self, state: &mut M::State, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        let (t, _u) = self.matcher.resume(state, bs)?;
        Ok(t)
    }
}

/// Builder-style helpers for matchers producing pairs, typically from
/// [`Matcher::then`] on an accumulator created with [`unit()`].
pub trait ParserExt<T, U>: Sized {
    /// Store the second value into the first one with `f`, producing the first one.
    fn save<F: Fn(&mut T, U)>(self, f: F) -> Save<Self, T, U, F>;

    /// Drop the second value, producing the first one.
    fn skip(self) -> Skip<Self, T, U>;
}

impl<M, T, U> ParserExt<T, U> for M
where
    M: Matcher<(T, U)> + Sized,
{
    fn save<F: Fn(&mut T, U)>(self, f: F) -> Save<Self, T, U, F> {
        Save {
            matcher: self,
            func: f,
            phantom: PhantomData,
        }
    }

    fn skip(self) -> Skip<Self, T, U> {
        Skip {
            matcher: self,
            phantom: PhantomData,
        }
    }
}

fn incomplete(bs: &ByteStream<'_>, requested: usize) -> MatchError {
    MatchError::incomplete(bs.offset(), requested, bs.remaining())
}

/// Match the byte `b`.
pub fn one(b: u8) -> impl Matcher<u8> {
    move |bs: &mut ByteStream| match bs.peek() {
        Some(x) if x == b => {
            bs.next();
            Ok(x)
        }
        Some(x) => Err(MatchError::unexpected_byte(bs.offset(), Some(x), b)),
        None => Err(incomplete(bs, 1)),
    }
}

/// Match the byte whose value is `chr` (compared as `byte as char`).
pub fn single(chr: char) -> impl Matcher<char> {
    move |bs: &mut ByteStream| match bs.peek() {
        Some(x) if x as char == chr => {
            bs.next();
            Ok(chr)
        }
        Some(x) => Err(match u8::try_from(chr) {
            Ok(b) => MatchError::unexpected_byte(bs.offset(), Some(x), b),
            Err(_) => MatchError::unexpected(bs.offset(), Some(x), format!("'{}'", chr)),
        }),
        None => Err(incomplete(bs, 1)),
    }
}

/// Matcher returned by [`take_while`].
pub struct TakeWhile<F>(F);

impl<F: Fn(u8) -> bool> Matcher<Vec<u8>> for TakeWhile<F> {
    type State = Vec<u8>;

    fn resume(&self, acc: &mut Vec<u8>, bs: &mut ByteStream<'_>) -> Result<Vec<u8>, MatchError> {
        let pos = bs.pos();
        let end = bs.find_single(|b| !(self.0)(*b));
        let n = end.map_or(bs.remaining(), |idx| idx - pos);
        let more = end.is_none() && !bs.is_closed();
        let chunk = bs.take(n).expect("n <= remaining");
        if more {
            // more matching bytes might still arrive
            acc.extend_from_slice(chunk);
            return Err(incomplete(bs, 1));
        }
        if acc.is_empty() {
            Ok(chunk.to_vec())
        } else {
            acc.extend_from_slice(chunk);
            Ok(mem::take(acc))
        }
    }
}

/// Take bytes while they match the predicate (possibly none).
///
/// On an open stream, running out of input before a non-matching byte is
/// `Incomplete`; on a closed one it ends the match.
pub fn take_while<F: Fn(u8) -> bool>(f: F) -> TakeWhile<F> {
    TakeWhile(f)
}

/// Matcher returned by [`take_while1`].
pub struct TakeWhile1<F> {
    inner: TakeWhile<F>,
    what: &'static str,
}

impl<F: Fn(u8) -> bool> Matcher<Vec<u8>> for TakeWhile1<F> {
    type State = Vec<u8>;

    fn resume(&self, acc: &mut Vec<u8>, bs: &mut ByteStream<'_>) -> Result<Vec<u8>, MatchError> {
        let vec = self.inner.resume(acc, bs)?;
        if vec.is_empty() {
            return Err(match bs.peek() {
                None => incomplete(bs, 1),
                found => MatchError::unexpected(bs.offset(), found, self.what),
            });
        }
        Ok(vec)
    }
}

/// Like [`take_while`], but at least one byte must match; `what` describes the expected
/// input in the error message.
pub fn take_while1<F: Fn(u8) -> bool>(f: F, what: &'static str) -> TakeWhile1<F> {
    TakeWhile1 {
        inner: take_while(f),
        what,
    }
}

/// Old name of [`take_while`].
#[deprecated(since = "0.4.0", note = "renamed to `take_while`")]
pub fn until<F: Fn(u8) -> bool>(f: F) -> TakeWhile<F> {
    take_while(f)
}

/// Matcher returned by [`before`].
pub struct Before(Option<u8>);

impl Matcher<Vec<u8>> for Before {
    type State = Vec<u8>;

    fn resume(&self, acc: &mut Vec<u8>, bs: &mut ByteStream<'_>) -> Result<Vec<u8>, MatchError> {
        let data = bs.as_ref();
        // a char beyond U+00FF never equals a byte
        let found = self.0.and_then(|b| memchr(b, data));
        let n = found.unwrap_or(data.len());
        let more = found.is_none() && !bs.is_closed();
        let chunk = bs.take(n).expect("n <= remaining");
        if more {
            acc.extend_from_slice(chunk);
            return Err(incomplete(bs, 1));
        }
        if acc.is_empty() {
            Ok(chunk.to_vec())
        } else {
            acc.extend_from_slice(chunk);
            Ok(mem::take(acc))
        }
    }
}

/// Take bytes up to (not including) the byte `chr` (like [`take_while`]: at the end of a
/// closed stream, everything). Bytes are compared as `byte as char`.
pub fn before(chr: char) -> Before {
    Before(u8::try_from(chr).ok())
}

/// Take bytes up to (not including) a space, as a string.
pub fn token() -> impl Matcher<String> {
    before(' ').map(|vec| vec.into_iter().map(|b| b as char).collect::<String>())
}

/// Match exactly the bytes of `slice`, producing nothing (no allocation, unlike [`exact`]).
pub fn tag(slice: &[u8]) -> impl Matcher<()> {
    move |bs: &mut ByteStream| {
        let rest = bs.as_ref();
        if rest.starts_with(slice) {
            bs.take(slice.len());
            return Ok(());
        }
        match rest.iter().zip(slice).position(|(a, b)| a != b) {
            Some(i) => Err(MatchError::unexpected_byte(
                bs.offset() + i,
                Some(rest[i]),
                slice[i],
            )),
            // what is available is a proper prefix of `slice`
            None => Err(incomplete(bs, slice.len())),
        }
    }
}

/// Match exactly the bytes of `slice`, producing a copy of them.
pub fn exact(slice: &[u8]) -> impl Matcher<Vec<u8>> {
    tag(slice).map(move |_| slice.to_vec())
}

/// Match exactly the bytes of `s`, producing it as a `String`.
pub fn string(s: &str) -> impl Matcher<String> {
    exact(s.as_bytes()).map(move |_| s.to_string())
}

/// Take whitespace bytes (possibly none).
pub fn space() -> impl Matcher<Vec<char>> {
    take_while(|b| (b as char).is_whitespace())
        .map(|vec| vec.into_iter().map(|b| b as char).collect())
}

/// Matcher returned by [`bytes`].
pub struct Bytes(usize);

impl Matcher<Vec<u8>> for Bytes {
    type State = Vec<u8>;

    fn resume(&self, acc: &mut Vec<u8>, bs: &mut ByteStream<'_>) -> Result<Vec<u8>, MatchError> {
        let n = self.0;
        if acc.is_empty() && bs.remaining() >= n {
            return Ok(bs.get(n).expect("n <= remaining"));
        }
        // no up-front allocation of `n` bytes: `n` may come from untrusted input
        let k = (n - acc.len()).min(bs.remaining());
        acc.extend_from_slice(bs.take(k).expect("k <= remaining"));
        if acc.len() == n {
            Ok(mem::take(acc))
        } else {
            Err(incomplete(bs, n - acc.len()))
        }
    }
}

/// Take exactly `len` bytes. Bytes are accumulated as they arrive, so `len` may exceed
/// the buffer capacity.
pub fn bytes(len: usize) -> Bytes {
    Bytes(len)
}

/// Matcher returned by [`rest`].
pub struct Rest;

impl Matcher<Vec<u8>> for Rest {
    type State = Vec<u8>;

    fn resume(&self, acc: &mut Vec<u8>, bs: &mut ByteStream<'_>) -> Result<Vec<u8>, MatchError> {
        let n = bs.remaining();
        let closed = bs.is_closed();
        let chunk = bs.take(n).expect("n == remaining");
        if acc.is_empty() && closed {
            return Ok(chunk.to_vec());
        }
        acc.extend_from_slice(chunk);
        if closed {
            Ok(mem::take(acc))
        } else {
            Err(incomplete(bs, 1))
        }
    }
}

/// Take all bytes until the end of the stream (or frame, see [`sized`]); on an open
/// stream, `Incomplete` until it is closed.
pub fn rest() -> Rest {
    Rest
}

// Zero-copy matchers: they only advance the stream, combine with `recognize` to get the
// offsets of what was matched.

/// Matcher returned by [`skip_while`].
pub struct SkipWhile<F>(F);

impl<F: Fn(u8) -> bool> Matcher<()> for SkipWhile<F> {
    // skipped bytes are consumed as they are seen: nothing to keep
    type State = ();

    fn resume(&self, _: &mut (), bs: &mut ByteStream<'_>) -> Result<(), MatchError> {
        let pos = bs.pos();
        match bs.find_single(|b| !(self.0)(*b)) {
            Some(idx) => {
                bs.skip(idx - pos);
                Ok(())
            }
            None => {
                bs.skip(bs.remaining());
                if bs.is_closed() {
                    Ok(())
                } else {
                    Err(incomplete(bs, 1))
                }
            }
        }
    }
}

/// Like [`take_while`], without copying the bytes.
pub fn skip_while<F: Fn(u8) -> bool>(f: F) -> SkipWhile<F> {
    SkipWhile(f)
}

/// Matcher returned by [`skip_while1`].
pub struct SkipWhile1<F> {
    inner: SkipWhile<F>,
    what: &'static str,
}

impl<F: Fn(u8) -> bool> Matcher<()> for SkipWhile1<F> {
    // whether any byte matched yet
    type State = bool;

    fn resume(&self, seen: &mut bool, bs: &mut ByteStream<'_>) -> Result<(), MatchError> {
        let pos = bs.pos();
        let result = self.inner.resume(&mut (), bs);
        *seen |= bs.pos() != pos;
        result?;
        if !*seen {
            return Err(match bs.peek() {
                None => incomplete(bs, 1),
                found => MatchError::unexpected(bs.offset(), found, self.what),
            });
        }
        *seen = false;
        Ok(())
    }
}

/// Like [`take_while1`], without copying the bytes.
pub fn skip_while1<F: Fn(u8) -> bool>(f: F, what: &'static str) -> SkipWhile1<F> {
    SkipWhile1 {
        inner: skip_while(f),
        what,
    }
}

/// Matcher returned by [`advance`].
pub struct Advance(usize);

impl Matcher<()> for Advance {
    // number of bytes skipped so far
    type State = usize;

    fn resume(&self, done: &mut usize, bs: &mut ByteStream<'_>) -> Result<(), MatchError> {
        *done += bs.skip(self.0 - *done);
        if *done == self.0 {
            *done = 0;
            Ok(())
        } else {
            Err(incomplete(bs, self.0 - *done))
        }
    }
}

/// Like [`bytes`], without copying the bytes.
pub fn advance(len: usize) -> Advance {
    Advance(len)
}

/// Matcher returned by [`spanned`].
pub struct Spanned<M>(M);

impl<M: Matcher<T>, T> Matcher<(T, Range<usize>)> for Spanned<M> {
    type State = StartState<M::State>;

    fn resume(
        &self,
        state: &mut Self::State,
        bs: &mut ByteStream<'_>,
    ) -> Result<(T, Range<usize>), MatchError> {
        let (t, start) = state.resume(&self.0, bs)?;
        Ok((t, start..bs.offset()))
    }
}

/// Match `this`, also producing the range of stream offsets it consumed.
/// See [`ByteStream::slice`] to get the bytes.
pub fn spanned<T, M: Matcher<T>>(this: M) -> Spanned<M> {
    Spanned(this)
}

/// Match `this`, producing only the range of stream offsets it consumed: with
/// [`skip_while`] and [`advance`], a zero-copy alternative to [`take_while`] and [`bytes`].
///
/// ```
/// use parsed::parser::{recognize, skip_while, Applicator, Matcher};
/// use parsed::stream::ByteStream;
///
/// let input = b"hello world";
/// let mut bs = ByteStream::borrow(input);
/// let word = bs.apply(recognize(skip_while(|b| b != b' '))).unwrap();
/// assert_eq!(&input[word], b"hello");
/// ```
pub fn recognize<T, M: Matcher<T>>(this: M) -> impl Matcher<Range<usize>> {
    spanned(this).map(|(_, range)| range)
}

/// Matcher returned by [`repeat`].
pub struct Repeat<M, T> {
    item: M,
    phantom: PhantomData<fn() -> T>,
}

/// State of [`Repeat`].
pub struct RepeatState<T, S> {
    acc: Vec<T>,
    item: S,
    // the item in progress has consumed input, so it is committed
    consumed: bool,
}

impl<T, S: Default> Default for RepeatState<T, S> {
    fn default() -> Self {
        RepeatState {
            acc: Vec::new(),
            item: S::default(),
            consumed: false,
        }
    }
}

impl<M: Matcher<T>, T: Send> Matcher<Vec<T>> for Repeat<M, T> {
    type State = RepeatState<T, M::State>;

    fn resume(
        &self,
        state: &mut Self::State,
        bs: &mut ByteStream<'_>,
    ) -> Result<Vec<T>, MatchError> {
        loop {
            match try_item(&self.item, &mut state.item, &mut state.consumed, bs) {
                Step::Matched(t) => state.acc.push(t),
                Step::End => return Ok(mem::take(&mut state.acc)),
                Step::Failed(e) => return Err(e),
            }
        }
    }
}

enum Step<T> {
    Matched(T),
    End,
    Failed(MatchError),
}

// One attempt at an optional item, shared by `repeat` and `maybe`: the item is optional
// as long as it has not consumed input.
fn try_item<M: Matcher<T>, T>(
    item: &M,
    state: &mut M::State,
    consumed: &mut bool,
    bs: &mut ByteStream,
) -> Step<T> {
    // `state` is at its default here, or holds only results of steps that consumed nothing
    if !*consumed && bs.remaining() == 0 {
        return if bs.is_closed() {
            Step::End
        } else {
            Step::Failed(incomplete(bs, 1))
        };
    }
    let pos = bs.pos();
    let result = item.resume(state, bs);
    let moved = bs.pos() != pos;
    let fresh = !*consumed && !moved;
    match result {
        // an item matching nothing would repeat forever
        Ok(_) if fresh => Step::End,
        Ok(t) => {
            *consumed = false;
            Step::Matched(t)
        }
        Err(e) if e.is_incomplete() && !(fresh && bs.is_closed()) => {
            *consumed |= moved;
            Step::Failed(e)
        }
        Err(_) if fresh => {
            *state = M::State::default();
            Step::End
        }
        Err(e) => {
            *consumed = false;
            *state = M::State::default();
            Step::Failed(e)
        }
    }
}

/// Match `this` as many times as possible (possibly none).
///
/// Repetition ends at an item that fails without consuming input, or at the end of a
/// closed stream (at the end of an open stream it is `Incomplete`).
pub fn repeat<T, M: Matcher<T>>(this: M) -> Repeat<M, T> {
    Repeat {
        item: this,
        phantom: PhantomData,
    }
}

/// Matcher returned by [`maybe`].
pub struct Maybe<M, T> {
    item: M,
    phantom: PhantomData<fn() -> T>,
}

/// State of [`Maybe`].
#[derive(Default)]
pub struct MaybeState<S> {
    item: S,
    consumed: bool,
}

impl<M: Matcher<T>, T> Matcher<Option<T>> for Maybe<M, T> {
    type State = MaybeState<M::State>;

    fn resume(
        &self,
        state: &mut Self::State,
        bs: &mut ByteStream,
    ) -> Result<Option<T>, MatchError> {
        match try_item(&self.item, &mut state.item, &mut state.consumed, bs) {
            Step::Matched(t) => Ok(Some(t)),
            Step::End => Ok(None),
            Step::Failed(e) => Err(e),
        }
    }
}

/// Match `this` if possible: `None` if it fails without consuming input, or at the end
/// of a closed stream (at the end of an open stream it is `Incomplete`).
pub fn maybe<T, M: Matcher<T>>(this: M) -> Maybe<M, T> {
    Maybe {
        item: this,
        phantom: PhantomData,
    }
}

/// Matcher returned by [`times`].
pub struct Times<M, T> {
    count: usize,
    item: M,
    phantom: PhantomData<fn() -> T>,
}

/// State of [`Times`] and [`RepeatUntil`].
pub struct ItemsState<T, S> {
    acc: Vec<T>,
    item: S,
}

impl<T, S: Default> Default for ItemsState<T, S> {
    fn default() -> Self {
        ItemsState {
            acc: Vec::new(),
            item: S::default(),
        }
    }
}

impl<M: Matcher<T>, T: Send> Matcher<Vec<T>> for Times<M, T> {
    type State = ItemsState<T, M::State>;

    fn resume(
        &self,
        state: &mut Self::State,
        bs: &mut ByteStream<'_>,
    ) -> Result<Vec<T>, MatchError> {
        while state.acc.len() < self.count {
            let t = self.item.resume(&mut state.item, bs)?;
            state.acc.push(t);
        }
        Ok(mem::take(&mut state.acc))
    }
}

/// Match `this` exactly `count` times.
pub fn times<T, M: Matcher<T>>(count: usize, this: M) -> Times<M, T> {
    Times {
        count,
        item: this,
        phantom: PhantomData,
    }
}

/// Matcher returned by [`repeat_until`].
pub struct RepeatUntil<M, T, F> {
    item: M,
    done: F,
    phantom: PhantomData<fn() -> T>,
}

impl<M: Matcher<T>, T: Send, F: Fn(&T) -> bool> Matcher<Vec<T>> for RepeatUntil<M, T, F> {
    type State = ItemsState<T, M::State>;

    fn resume(
        &self,
        state: &mut Self::State,
        bs: &mut ByteStream<'_>,
    ) -> Result<Vec<T>, MatchError> {
        loop {
            let t = self.item.resume(&mut state.item, bs)?;
            let last = (self.done)(&t);
            state.acc.push(t);
            if last {
                return Ok(mem::take(&mut state.acc));
            }
        }
    }
}

/// Match `this` repeatedly until it produces an item for which `done` is true
/// (that item included), e.g. a list terminated by a sentinel.
pub fn repeat_until<T, M: Matcher<T>, F: Fn(&T) -> bool>(this: M, done: F) -> RepeatUntil<M, T, F> {
    RepeatUntil {
        item: this,
        done,
        phantom: PhantomData,
    }
}

/// Matcher returned by [`limit`].
pub struct Limit<M> {
    max: usize,
    inner: M,
}

/// State of [`Limit`].
#[derive(Default)]
pub struct LimitState<S> {
    start: Option<usize>,
    consumed: usize,
    inner: S,
}

impl<M: Matcher<T>, T> Matcher<T> for Limit<M> {
    type State = LimitState<M::State>;

    fn resume(&self, state: &mut Self::State, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        let start = bs.offset();
        let first = *state.start.get_or_insert(start);
        // the inner matcher sees at most one byte beyond the limit
        let allowed = (self.max - state.consumed).saturating_add(1);
        let window = bs.restrict(allowed);
        let result = self.inner.resume(&mut state.inner, bs);
        let restricted = bs.is_restricted();
        bs.unrestrict(window);
        state.consumed += bs.offset() - start;
        let needs_more = restricted && matches!(&result, Err(e) if e.is_incomplete());
        if state.consumed > self.max || needs_more {
            return Err(MatchError::too_large(
                first,
                format!("limit of {} bytes exceeded", self.max),
            ));
        }
        if result.is_ok() {
            state.consumed = 0;
            state.start = None;
        }
        result
    }
}

/// Fail with [`ErrorKind::TooLarge`] if `this` needs more than `max` bytes of input.
///
/// `this` never sees more than `max + 1` bytes (one byte of lookahead), so the limit also
/// bounds the work done and the memory held by a resumable match.
pub fn limit<T, M: Matcher<T>>(max: usize, this: M) -> Limit<M> {
    Limit { max, inner: this }
}

/// Matcher returned by [`attempt`].
pub struct Attempt<M>(M);

impl<M: Matcher<T>, T> Matcher<T> for Attempt<M> {
    type State = ();

    fn resume(&self, _: &mut (), bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        self.0.do_match(bs)
    }
}

/// Make `this` atomic: on any error nothing is consumed, so [`repeat`] and [`maybe`]
/// can backtrack over it. The price is that it restarts from scratch on `Incomplete`,
/// so the input it matches must fit into the buffer.
pub fn attempt<T, M: Matcher<T>>(this: M) -> Attempt<M> {
    Attempt(this)
}

/// One of two matchers producing the same type, e.g. to return different matchers
/// from [`Matcher::then_with`].
pub enum Either<A, B> {
    /// The first matcher.
    Left(A),
    /// The second matcher.
    Right(B),
}

/// State of [`Either`].
#[derive(Default)]
pub struct EitherState<A, B> {
    left: A,
    right: B,
}

impl<A: Matcher<T>, B: Matcher<T>, T> Matcher<T> for Either<A, B> {
    type State = EitherState<A::State, B::State>;

    fn resume(&self, state: &mut Self::State, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        match self {
            Either::Left(a) => a.resume(&mut state.left, bs),
            Either::Right(b) => b.resume(&mut state.right, bs),
        }
    }
}

// Sequencing without nested tuples

/// Match `first`, then `second`, producing the value of `second`.
pub fn preceded<T: Send, U>(first: impl Matcher<T>, second: impl Matcher<U>) -> impl Matcher<U> {
    first.ignore_then(second)
}

/// Match `first`, then `second`, producing the value of `first`.
pub fn terminated<T: Send, U>(first: impl Matcher<T>, second: impl Matcher<U>) -> impl Matcher<T> {
    first.then_ignore(second)
}

/// Match `open`, `inner` and `close`, producing the value of `inner`.
pub fn delimited<T: Send, U: Send, V>(
    open: impl Matcher<T>,
    inner: impl Matcher<U>,
    close: impl Matcher<V>,
) -> impl Matcher<U> {
    open.ignore_then(inner).then_ignore(close)
}

/// Matcher returned by [`separated`].
pub struct Separated<M, S, T, U> {
    item: M,
    sep: S,
    phantom: PhantomData<fn() -> (T, U)>,
}

/// State of [`Separated`].
pub struct SeparatedState<T, A, B> {
    acc: Vec<T>,
    phase: SeparatedPhase,
    item: A,
    sep: B,
    consumed: bool,
}

#[derive(Clone, Copy)]
enum SeparatedPhase {
    First,
    Sep,
    Item,
}

impl<T, A: Default, B: Default> Default for SeparatedState<T, A, B> {
    fn default() -> Self {
        SeparatedState {
            acc: Vec::new(),
            phase: SeparatedPhase::First,
            item: A::default(),
            sep: B::default(),
            consumed: false,
        }
    }
}

impl<M: Matcher<T>, S: Matcher<U>, T: Send, U> Matcher<Vec<T>> for Separated<M, S, T, U> {
    type State = SeparatedState<T, M::State, S::State>;

    fn resume(
        &self,
        state: &mut Self::State,
        bs: &mut ByteStream<'_>,
    ) -> Result<Vec<T>, MatchError> {
        loop {
            match state.phase {
                SeparatedPhase::First => {
                    match try_item(&self.item, &mut state.item, &mut state.consumed, bs) {
                        Step::Matched(t) => {
                            state.acc.push(t);
                            state.phase = SeparatedPhase::Sep;
                        }
                        Step::End => return Ok(mem::take(state).acc),
                        Step::Failed(e) => return Err(e),
                    }
                }
                SeparatedPhase::Sep => {
                    match try_item(&self.sep, &mut state.sep, &mut state.consumed, bs) {
                        Step::Matched(_) => state.phase = SeparatedPhase::Item,
                        Step::End => return Ok(mem::take(state).acc),
                        Step::Failed(e) => return Err(e),
                    }
                }
                // an item must follow a separator
                SeparatedPhase::Item => {
                    let t = self.item.resume(&mut state.item, bs)?;
                    state.acc.push(t);
                    state.phase = SeparatedPhase::Sep;
                }
            }
        }
    }
}

/// Match a possibly empty list of `item`s separated by `sep`: `item (sep item)*`.
/// A separator must be followed by an item.
///
/// ```
/// use parsed::parser::{decimal, separated, tag, Applicator};
/// use parsed::stream::ByteStream;
///
/// let list = separated(decimal(), tag(b","));
/// assert_eq!(ByteStream::borrow(b"1,22,333").apply(list), Ok(vec![1, 22, 333]));
/// ```
pub fn separated<T, U, M: Matcher<T>, S: Matcher<U>>(item: M, sep: S) -> Separated<M, S, T, U> {
    Separated {
        item,
        sep,
        phantom: PhantomData,
    }
}

// Search and framing

// Index of the first `byte` in `haystack`, 8 bytes at a time.
pub(crate) fn memchr(byte: u8, haystack: &[u8]) -> Option<usize> {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    let pattern = LO * byte as u64;
    let mut chunks = haystack.chunks_exact(8);
    for (i, chunk) in (&mut chunks).enumerate() {
        let x = u64::from_le_bytes(chunk.try_into().expect("8 bytes")) ^ pattern;
        // a zero byte in `x` is a match
        let found = x.wrapping_sub(LO) & !x & HI;
        if found != 0 {
            return Some(i * 8 + (found.trailing_zeros() / 8) as usize);
        }
    }
    let tail = haystack.len() - chunks.remainder().len();
    chunks
        .remainder()
        .iter()
        .position(|b| *b == byte)
        .map(|i| tail + i)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let Some((&first, rest)) = needle.split_first() else {
        return Some(0);
    };
    let mut from = 0;
    while let Some(i) = memchr(first, &haystack[from..]) {
        let at = from + i;
        let tail = haystack.get(at + 1..at + needle.len())?;
        if tail == rest {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// Matcher returned by [`take_until`].
pub struct TakeUntil<'p>(&'p [u8]);

impl Matcher<Vec<u8>> for TakeUntil<'_> {
    type State = Vec<u8>;

    fn resume(&self, acc: &mut Vec<u8>, bs: &mut ByteStream<'_>) -> Result<Vec<u8>, MatchError> {
        let data = bs.as_ref();
        if let Some(i) = find(data, self.0) {
            acc.extend_from_slice(&data[..i]);
            bs.skip(i);
            return Ok(mem::take(acc));
        }
        if !bs.is_closed() {
            // the last bytes may be the start of the pattern: keep them for the next try
            let n = data.len().saturating_sub(self.0.len() - 1);
            acc.extend_from_slice(&data[..n]);
            bs.skip(n);
        }
        Err(incomplete(bs, self.0.len()))
    }
}

/// Take bytes up to (not including) the first occurrence of `pattern`. Bytes are
/// accumulated as they arrive, so the output may be larger than the buffer; the pattern
/// itself must fit. Without the pattern, the end of a closed stream is `Incomplete`
/// (the input is truncated).
///
/// ```
/// use parsed::parser::{tag, take_until, Applicator, Matcher};
/// use parsed::stream::ByteStream;
///
/// let line = take_until(b"\r\n").then_ignore(tag(b"\r\n"));
/// assert_eq!(ByteStream::borrow(b"PING\r\n").apply(line), Ok(b"PING".to_vec()));
/// ```
pub fn take_until(pattern: &[u8]) -> TakeUntil<'_> {
    TakeUntil(pattern)
}

/// Matcher returned by [`skip_until`].
pub struct SkipUntil<'p>(&'p [u8]);

impl Matcher<()> for SkipUntil<'_> {
    type State = ();

    fn resume(&self, _: &mut (), bs: &mut ByteStream<'_>) -> Result<(), MatchError> {
        let data = bs.as_ref();
        if let Some(i) = find(data, self.0) {
            bs.skip(i);
            return Ok(());
        }
        if !bs.is_closed() {
            let n = data.len().saturating_sub(self.0.len() - 1);
            bs.skip(n);
        }
        Err(incomplete(bs, self.0.len()))
    }
}

/// Like [`take_until`], without copying the bytes (see [`recognize`]).
pub fn skip_until(pattern: &[u8]) -> SkipUntil<'_> {
    SkipUntil(pattern)
}

/// Matcher returned by [`sized`].
pub struct SizedFrame<M> {
    len: usize,
    inner: M,
}

/// State of [`SizedFrame`].
#[derive(Default)]
pub struct SizedState<S> {
    done: usize,
    inner: S,
}

impl<M: Matcher<T>, T> Matcher<T> for SizedFrame<M> {
    type State = SizedState<M::State>;

    fn resume(&self, state: &mut Self::State, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        let window = bs.restrict_frame(self.len - state.done);
        let buffered = bs.is_frame_buffered();
        let start = bs.pos();
        let result = self.inner.resume(&mut state.inner, bs);
        bs.unrestrict(window);
        state.done += bs.pos() - start;
        match result {
            Ok(t) if state.done == self.len => {
                state.done = 0;
                Ok(t)
            }
            Ok(_) => Err(MatchError::invalid(
                bs.offset(),
                "unconsumed bytes at the end of the frame",
            )),
            // the whole frame is visible, and still not enough
            Err(e) if e.is_incomplete() && buffered => {
                Err(MatchError::invalid(e.offset(), "frame too short"))
            }
            Err(e) => Err(e),
        }
    }
}

/// Match `inner` against exactly the next `len` bytes, as a frame of their own: `inner`
/// sees the end of the frame as the end of (closed) input, and must consume all of it.
/// Typically used for length-prefixed data, see [`length_prefixed`].
pub fn sized<T, M: Matcher<T>>(len: usize, inner: M) -> SizedFrame<M> {
    SizedFrame { len, inner }
}

/// Match a length (e.g. [`get_u16`] or [`varint`]), then `inner()` against a frame of
/// that many bytes (see [`sized`]).
///
/// ```
/// use parsed::parser::{get_u8, length_prefixed, rest, Applicator};
/// use parsed::stream::ByteStream;
///
/// let m = length_prefixed(get_u8(), rest);
/// assert_eq!(ByteStream::borrow(b"\x03abcd").apply(m), Ok(b"abc".to_vec()));
/// ```
pub fn length_prefixed<N, T, L, M, F>(len: L, inner: F) -> impl Matcher<T>
where
    N: Copy + Into<u64>,
    L: Matcher<N>,
    M: Matcher<T> + Send,
    F: Fn() -> M,
{
    len.try_map(|n: N| usize::try_from(n.into()).map_err(|_| "length too large"))
        .then_with(move |n| sized(*n, inner()))
        .map(|(_, t)| t)
}

// Lookahead

/// Match `this` without consuming input. `this` is retried from scratch on `Incomplete`.
pub fn peek<T>(this: impl Matcher<T>) -> impl Matcher<T> {
    move |bs: &mut ByteStream<'_>| {
        let mark = bs.mark();
        let result = this.do_match(bs);
        bs.reset(mark);
        result
    }
}

/// Succeed (without consuming input) if `this` does not match here.
pub fn not<T>(this: impl Matcher<T>) -> impl Matcher<()> {
    move |bs: &mut ByteStream<'_>| {
        let mark = bs.mark();
        let offset = bs.offset();
        let result = this.do_match(bs);
        bs.reset(mark);
        match result {
            Ok(_) => Err(MatchError::unexpected(offset, bs.peek(), "something else")),
            Err(e) if e.is_incomplete() && !bs.is_closed() => Err(e),
            Err(_) => Ok(()),
        }
    }
}

/// Match the end of input: of a closed stream, or of a frame (see [`sized`]).
pub fn eof() -> impl Matcher<()> {
    |bs: &mut ByteStream<'_>| match bs.peek() {
        Some(b) => Err(MatchError::unexpected(bs.offset(), Some(b), "end of input")),
        None if bs.is_closed() => Ok(()),
        None => Err(incomplete(bs, 1)),
    }
}

/// Always fail with `message` (e.g. in one arm of a choice made with
/// [`Matcher::then_with`] and [`Either`]).
pub fn fail<T>(message: &'static str) -> impl Matcher<T> {
    move |bs: &mut ByteStream<'_>| Err(MatchError::invalid(bs.offset(), message))
}

/// Matcher returned by [`lazy`].
pub struct Lazy<F, M> {
    f: F,
    matcher: std::sync::OnceLock<M>,
}

impl<F: Fn() -> M, M: Matcher<T>, T> Matcher<T> for Lazy<F, M> {
    type State = M::State;

    fn resume(&self, state: &mut M::State, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        self.matcher.get_or_init(&self.f).resume(state, bs)
    }
}

/// A matcher built by `f` when it is first used (once, then reused): for recursive
/// grammars, where a matcher contains itself. `f` must return a
/// [`Boxed`](crate::matcher::Boxed) matcher to break the type recursion. Nesting depth is
/// bounded only by the stack: limit it, as in the example.
///
/// ```
/// use parsed::matcher::Boxed;
/// use parsed::parser::{delimited, fail, lazy, separated, tag, Applicator, Matcher};
/// use parsed::stream::ByteStream;
///
/// // nested lists like "[[],[[]]]", returning the maximum depth
/// fn list(depth: usize) -> Boxed<usize> {
///     if depth > 32 {
///         return fail("too deeply nested").boxed();
///     }
///     let items = separated(lazy(move || list(depth + 1)), tag(b","));
///     delimited(tag(b"["), items, tag(b"]"))
///         .map(|items| 1 + items.into_iter().max().unwrap_or(0))
///         .boxed()
/// }
///
/// assert_eq!(ByteStream::borrow(b"[[],[[]]]").apply(list(0)), Ok(3));
/// assert!(ByteStream::borrow("[".repeat(100).as_bytes()).apply(list(0)).is_err());
/// ```
pub fn lazy<T, M: Matcher<T>, F: Fn() -> M>(f: F) -> Lazy<F, M> {
    Lazy {
        f,
        matcher: std::sync::OnceLock::new(),
    }
}

// Numbers

/// Read a little-endian `u16`.
pub fn get_u16_le() -> impl Matcher<u16> {
    move |bs: &mut ByteStream<'_>| {
        bs.get_array()
            .map(u16::from_le_bytes)
            .ok_or_else(|| incomplete(bs, 2))
    }
}

/// Read a little-endian `u32`.
pub fn get_u32_le() -> impl Matcher<u32> {
    move |bs: &mut ByteStream<'_>| {
        bs.get_array()
            .map(u32::from_le_bytes)
            .ok_or_else(|| incomplete(bs, 4))
    }
}

/// Read a little-endian `u64`.
pub fn get_u64_le() -> impl Matcher<u64> {
    move |bs: &mut ByteStream<'_>| {
        bs.get_array()
            .map(u64::from_le_bytes)
            .ok_or_else(|| incomplete(bs, 8))
    }
}

/// Read an unsigned LEB128 variable-length integer (as in protobuf), at most 10 bytes.
///
/// ```
/// use parsed::parser::{varint, Applicator};
/// use parsed::stream::ByteStream;
///
/// assert_eq!(ByteStream::borrow(&[0xAC, 0x02]).apply(varint()), Ok(300));
/// ```
pub fn varint() -> impl Matcher<u64> {
    move |bs: &mut ByteStream<'_>| {
        let mut value = 0u64;
        for (i, b) in bs.as_ref().iter().take(10).enumerate() {
            if i == 9 && *b > 1 {
                return Err(MatchError::invalid(bs.offset(), "varint overflows 64 bits"));
            }
            value |= ((b & 0x7F) as u64) << (7 * i);
            if b & 0x80 == 0 {
                bs.skip(i + 1);
                return Ok(value);
            }
        }
        if bs.remaining() >= 10 {
            return Err(MatchError::invalid(
                bs.offset(),
                "varint longer than 10 bytes",
            ));
        }
        Err(incomplete(bs, bs.remaining() + 1))
    }
}

/// Matcher returned by [`decimal`].
pub struct Decimal;

impl Matcher<u64> for Decimal {
    // value so far, and whether any digit was seen
    type State = (u64, bool);

    fn resume(&self, state: &mut (u64, bool), bs: &mut ByteStream<'_>) -> Result<u64, MatchError> {
        let data = bs.as_ref();
        let digits = data.iter().take_while(|b| b.is_ascii_digit()).count();
        let mut value = state.0;
        for (i, b) in data[..digits].iter().enumerate() {
            value = match value
                .checked_mul(10)
                .and_then(|v| v.checked_add((b - b'0') as u64))
            {
                Some(v) => v,
                None => {
                    let offset = bs.offset() + i;
                    return Err(MatchError::invalid(offset, "number overflows 64 bits"));
                }
            };
        }
        let at_end = digits == data.len();
        let found = data.get(digits).copied();
        bs.skip(digits);
        state.0 = value;
        state.1 |= digits > 0;
        if !state.1 {
            return Err(match found {
                None => incomplete(bs, 1),
                found => MatchError::unexpected(bs.offset(), found, "digit"),
            });
        }
        if at_end && !bs.is_closed() {
            // more digits may follow
            return Err(incomplete(bs, 1));
        }
        Ok(mem::take(state).0)
    }
}

/// Read an unsigned decimal number (ASCII digits, at least one) that fits into `u64`.
pub fn decimal() -> Decimal {
    Decimal
}

/// Read a signed decimal number (optional `-`, then digits) that fits into `i64`.
pub fn integer() -> impl Matcher<i64> {
    maybe(one(b'-'))
        .then(decimal())
        .try_map(|(sign, n)| match sign {
            None => i64::try_from(n).map_err(|_| "number overflows 64 bits"),
            Some(_) if n <= i64::MAX as u64 + 1 => Ok((n as i64).wrapping_neg()),
            Some(_) => Err("number overflows 64 bits"),
        })
}

/// Read a byte.
pub fn get_u8() -> impl Matcher<u8> {
    move |bs: &mut ByteStream| bs.get_u8().ok_or_else(|| incomplete(bs, 1))
}

/// Read a big-endian `u16`.
pub fn get_u16() -> impl Matcher<u16> {
    move |bs: &mut ByteStream| bs.get_u16().ok_or_else(|| incomplete(bs, 2))
}

/// Read a big-endian `u32`.
pub fn get_u32() -> impl Matcher<u32> {
    move |bs: &mut ByteStream| bs.get_u32().ok_or_else(|| incomplete(bs, 4))
}

/// Read a big-endian `u64`.
pub fn get_u64() -> impl Matcher<u64> {
    move |bs: &mut ByteStream| bs.get_u64().ok_or_else(|| incomplete(bs, 8))
}

/// Read 16 bytes.
pub fn get_16() -> impl Matcher<[u8; 16]> {
    move |bs: &mut ByteStream| bs.get_16().ok_or_else(|| incomplete(bs, 16))
}

/// Read 32 bytes.
pub fn get_32() -> impl Matcher<[u8; 32]> {
    move |bs: &mut ByteStream| bs.get_32().ok_or_else(|| incomplete(bs, 32))
}

/// Apply a matcher to a stream.
pub trait Applicator {
    /// One-shot match, see [`Matcher::do_match`].
    fn apply<T>(&mut self, parser: impl Matcher<T>) -> Result<T, MatchError>;
}

impl Applicator for ByteStream<'_> {
    fn apply<T>(&mut self, parser: impl Matcher<T>) -> Result<T, MatchError> {
        parser.do_match(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{feed, open};

    #[test]
    fn simple() {
        #[derive(Debug, Eq, PartialEq)]
        enum Token {
            KV { k: char, v: char },
        }

        struct TokenBuilder {
            k: Option<char>,
            v: Option<char>,
        }

        impl TokenBuilder {
            fn zero() -> TokenBuilder {
                TokenBuilder { k: None, v: None }
            }
        }

        let mut bs: ByteStream = "abc".to_string().into();

        let m = unit(TokenBuilder::zero)
            .then_map(single('a'), |(tb, a)| TokenBuilder { k: Some(a), ..tb })
            .then_map(single('b'), |(tb, b)| TokenBuilder { v: Some(b), ..tb })
            .map(|tb| Token::KV {
                k: tb.k.unwrap(),
                v: tb.v.unwrap(),
            });

        assert_eq!(bs.apply(m).unwrap(), Token::KV { k: 'a', v: 'b' });
        assert_eq!(bs.pos(), 2);
    }

    #[test]
    fn list() {
        let mut bs: ByteStream = "abccc".to_string().into();

        let c = single('c');

        let abccc = unit(Vec::new)
            .then_map(single('a'), |(acc, a)| {
                let mut copy = acc.clone();
                copy.push(a);
                copy
            })
            .then_map(single('b'), |(acc, b)| {
                let mut copy = acc.clone();
                copy.push(b);
                copy
            })
            .then_map(repeat(c), |(acc, vec)| {
                let mut copy = acc;
                for item in vec {
                    copy.push(item);
                }
                copy
            });

        assert_eq!(bs.apply(abccc).unwrap(), vec!['a', 'b', 'c', 'c', 'c']);
        assert_eq!(bs.pos(), 5);
    }

    #[test]
    fn until() {
        let mut bs: ByteStream = "asdasdasdasd1".to_string().into();

        let until1 = unit(|| ())
            .then_map(before('1'), |(_, vec)| {
                vec.into_iter().map(|b| b as char).collect::<String>()
            })
            .then_map(single('1'), |(vec, one)| (vec, one));

        assert_eq!(bs.apply(until1).unwrap(), ("asdasdasdasd".to_string(), '1'));
    }

    #[test]
    fn chunks() {
        let mut bs: ByteStream = "asdasdqqq123123token1 token2\n".to_string().into();

        let m = unit(Vec::new)
            .then(exact("asd".as_bytes()))
            .map(|(mut vec, bs)| {
                vec.push(bs.into_iter().map(|b| b as char).collect::<String>());
                vec
            })
            .then(exact("asdqqq".as_bytes()))
            .map(|(mut vec, bs)| {
                vec.push(bs.into_iter().map(|b| b as char).collect::<String>());
                vec
            })
            .then(exact("123123".as_bytes()))
            .map(|(mut vec, bs)| {
                vec.push(bs.into_iter().map(|b| b as char).collect::<String>());
                vec
            })
            .then(token())
            .map(|(mut vec, bs)| {
                vec.push(bs);
                vec
            })
            .then(before('\n'))
            .map(|(mut vec, bs)| {
                vec.push(bs.into_iter().map(|b| b as char).collect::<String>());
                vec
            });

        assert_eq!(
            bs.apply(m).unwrap(),
            vec![
                "asd".to_string(),
                "asdqqq".to_string(),
                "123123".to_string(),
                "token1".to_string(),
                " token2".to_string(),
            ]
        );
    }

    #[test]
    fn test_times_ok() {
        let mut bs = ByteStream::wrap(b"012301230123".to_vec());

        let m = unit(|| ())
            .then(times(3, exact(b"0123")))
            .map(|(_, times)| times);

        assert_eq!(bs.apply(m).unwrap(), vec![b"0123", b"0123", b"0123",]);
    }

    #[test]
    fn test_times_mismatch() {
        let mut bs = ByteStream::wrap(b"0123012301AA".to_vec());

        let m = unit(Vec::new)
            .then(times(3, exact(b"0123")))
            .save(|vec, times| *vec = times);

        assert!(bs.apply(m).is_err());
    }

    #[test]
    fn single_mismatch_does_not_consume() {
        let mut bs = ByteStream::wrap(b"b".to_vec());
        let e = bs.apply(single('a')).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unexpected);
        assert_eq!(e.to_string(), "at offset 0: expected 'a' but found 'b'");
        assert_eq!(bs.pos(), 0);

        let e = bs.apply(one(b'a')).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unexpected);
        assert_eq!(bs.pos(), 0);
        assert_eq!(bs.apply(one(b'b')).unwrap(), b'b');

        assert!(bs.apply(single('b')).unwrap_err().is_incomplete());
    }

    #[test]
    fn exact_prefix_is_incomplete() {
        let mut bs = ByteStream::wrap(b"01".to_vec());
        assert!(bs.apply(exact(b"0123")).unwrap_err().is_incomplete());
        assert_eq!(bs.pos(), 0);

        let mut bs = ByteStream::wrap(b"01x3".to_vec());
        let e = bs.apply(exact(b"0123")).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unexpected);
        assert_eq!(e.offset(), 2);
        assert_eq!(bs.pos(), 0);

        assert_eq!(bs.apply(string("01x")).unwrap(), "01x");
        assert_eq!(bs.pos(), 3);
    }

    #[test]
    fn exact_non_static() {
        let pattern = vec![b'a', b'b'];
        let mut bs = ByteStream::wrap(b"ab".to_vec());
        assert_eq!(bs.apply(exact(&pattern)).unwrap(), pattern);
    }

    #[test]
    fn chain_resets_on_failure() {
        let mut bs = ByteStream::wrap(b"abX".to_vec());
        let m = single('a').then(single('b')).then(single('c'));
        assert!(bs.apply(m).is_err());
        assert_eq!(bs.pos(), 0);

        let m = single('a').then_with(|_| single('c'));
        assert!(bs.apply(m).is_err());
        assert_eq!(bs.pos(), 0);
    }

    #[test]
    fn test_times_zero() {
        let mut bs = ByteStream::wrap(b"ab".to_vec());
        assert_eq!(bs.apply(times(0, single('a'))).unwrap(), vec![]);
        assert_eq!(bs.pos(), 0);
    }

    #[test]
    fn test_times_mismatch_resets() {
        let mut bs = ByteStream::wrap(b"aab".to_vec());
        let e = bs.apply(times(3, single('a'))).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unexpected);
        assert_eq!(bs.pos(), 0);

        let mut bs = ByteStream::wrap(b"aa".to_vec());
        assert!(bs.apply(times(3, single('a'))).unwrap_err().is_incomplete());
        assert_eq!(bs.pos(), 0);
    }

    #[test]
    fn repeat_zero_width_terminates() {
        let mut bs = ByteStream::wrap(b"abc".to_vec());
        assert_eq!(bs.apply(repeat(maybe(single('x')))).unwrap().len(), 0);
        assert_eq!(bs.apply(repeat(unit(|| ()))).unwrap().len(), 0);
        assert_eq!(bs.pos(), 0);
    }

    #[test]
    fn repeat_at_end_of_input() {
        // closed stream: a truncated item that consumed nothing ends the repetition
        let mut bs = ByteStream::wrap(b"ababa".to_vec());
        assert_eq!(bs.apply(repeat(exact(b"ab"))).unwrap().len(), 2);
        assert_eq!(bs.pos(), 4);

        // open stream: more items might arrive
        let mut bs = open(b"ababa");
        assert!(bs.apply(repeat(exact(b"ab"))).unwrap_err().is_incomplete());
        let mut bs = open(b"abab");
        assert!(bs.apply(repeat(exact(b"ab"))).unwrap_err().is_incomplete());
        assert_eq!(bs.pos(), 0);

        let mut bs = open(b"ababX");
        assert_eq!(bs.apply(repeat(exact(b"ab"))).unwrap().len(), 2);
        assert_eq!(bs.pos(), 4);
    }

    #[test]
    fn repeat_commits_to_item_that_consumed_input() {
        let ab = || exact(b"a").then(exact(b"b"));
        let mut bs = ByteStream::wrap(b"abaX".to_vec());
        assert_eq!(bs.apply(repeat(ab())).unwrap_err().offset(), 3);
        assert_eq!(bs.pos(), 0);

        let mut bs = ByteStream::wrap(b"abaX".to_vec());
        assert_eq!(bs.apply(repeat(attempt(ab()))).unwrap().len(), 1);
        assert_eq!(bs.pos(), 2);
    }

    #[test]
    fn maybe_at_end_of_input() {
        let mut bs = ByteStream::wrap(b"a".to_vec());
        assert_eq!(bs.apply(maybe(exact(b"ab"))).unwrap(), None);
        let mut bs = open(b"a");
        assert!(bs.apply(maybe(exact(b"ab"))).unwrap_err().is_incomplete());
        let mut bs = ByteStream::wrap(b"x".to_vec());
        assert_eq!(bs.apply(maybe(exact(b"ab"))).unwrap(), None);
        let mut bs = ByteStream::wrap(vec![]);
        assert_eq!(bs.apply(maybe(exact(b"ab"))).unwrap(), None);
        let mut bs = open(b"");
        assert!(bs.apply(maybe(exact(b"ab"))).unwrap_err().is_incomplete());
    }

    #[test]
    fn take_while_at_end_of_input() {
        let mut bs = open(b"aaa");
        assert!(
            bs.apply(take_while(|b| b == b'a'))
                .unwrap_err()
                .is_incomplete()
        );
        assert!(bs.apply(before('!')).unwrap_err().is_incomplete());
        assert_eq!(bs.pos(), 0);

        let mut bs = ByteStream::wrap(b"aaa".to_vec());
        assert_eq!(bs.apply(take_while(|b| b == b'a')).unwrap(), b"aaa");

        let mut bs = ByteStream::wrap(b"  ".to_vec());
        assert_eq!(bs.apply(space()).unwrap(), vec![' ', ' ']);
    }

    #[test]
    fn binary_getters() {
        let mut bs = ByteStream::wrap(vec![1, 0, 2, 0, 0, 0, 3]);
        let m = get_u8().then(get_u16()).then(get_u32());
        assert_eq!(bs.apply(m).unwrap(), ((1, 2), 3));
        assert!(bs.apply(get_u64()).unwrap_err().is_incomplete());
    }

    #[test]
    fn resumable_keeps_completed_steps() {
        let m = before(' ')
            .then(exact(b" "))
            .then(bytes(3))
            .map(|((word, _), tail)| (word, tail));
        let mut parser = Resumable::new(m);
        let mut bs = ByteStream::with_capacity(8);

        bs.put(b"hel");
        assert!(parser.parse(&mut bs).unwrap_err().is_incomplete());
        assert_eq!(bs.remaining(), 0, "partial word is consumed into the state");
        bs.pull();
        bs.put(b"lo ");
        assert!(parser.parse(&mut bs).unwrap_err().is_incomplete());
        bs.pull();
        bs.put(b"ab");
        assert!(parser.parse(&mut bs).unwrap_err().is_incomplete());
        bs.pull();
        bs.put(b"cNEXT");
        assert_eq!(
            parser.parse(&mut bs).unwrap(),
            (b"hello".to_vec(), b"abc".to_vec())
        );
        assert_eq!(bs.as_ref(), b"NEXT");
    }

    #[test]
    fn resumable_bytes_larger_than_buffer() {
        let data: Vec<u8> = (0..200u8).collect();
        assert_eq!(feed(bytes(200), &data, 7, false).unwrap(), data);
    }

    #[test]
    fn resumable_atomic_step_is_retried() {
        let m = || exact(b"abcd").then(get_u16());
        let data = [b'a', b'b', b'c', b'd', 1, 2];
        for chunk in 1..data.len() {
            assert_eq!(feed(m(), &data, chunk, false).unwrap().1, 0x0102);
        }
    }

    #[test]
    fn resumable_restarts_after_error_and_success() {
        let mut parser = Resumable::new(exact(b"a").then(exact(b"b")));
        let mut bs = ByteStream::wrap(b"aXab".to_vec());
        assert!(!parser.parse(&mut bs).unwrap_err().is_incomplete());
        bs.next();
        assert!(parser.parse(&mut bs).is_ok());
    }

    #[test]
    fn test_repeat_until() {
        let item = get_u8();
        let mut bs = ByteStream::wrap(vec![3, 2, 0, 9]);
        assert_eq!(
            bs.apply(repeat_until(item, |b| *b == 0)).unwrap(),
            vec![3, 2, 0]
        );
        assert_eq!(bs.remaining(), 1);
    }

    #[test]
    fn test_limit() {
        let word = || limit(4, before(';'));
        let mut bs = ByteStream::wrap(b"abcd;".to_vec());
        assert_eq!(bs.apply(word()).unwrap(), b"abcd");
        let mut bs = ByteStream::wrap(b"abcde;".to_vec());
        let e = bs.apply(word()).unwrap_err();
        assert_eq!(e.to_string(), "at offset 0: limit of 4 bytes exceeded");
        // across resumes
        assert!(feed(word(), b"abcde;", 2, false).is_err());
        assert!(
            !feed(word(), b"abcde;", 2, false)
                .unwrap_err()
                .is_incomplete()
        );
        assert_eq!(feed(word(), b"abc;", 1, false).unwrap(), b"abc");
    }

    #[test]
    fn test_either_and_try_map() {
        let m = || {
            get_u8()
                .try_map(|n| {
                    if n < 10 {
                        Ok(n as usize)
                    } else {
                        Err("too long")
                    }
                })
                .then_with(|&n| {
                    if n == 0 {
                        Either::Left(unit(Vec::new))
                    } else {
                        Either::Right(bytes(n))
                    }
                })
                .map(|(_, v)| v)
        };
        assert_eq!(
            ByteStream::wrap(vec![2, 7, 8]).apply(m()).unwrap(),
            vec![7, 8]
        );
        assert_eq!(ByteStream::wrap(vec![0]).apply(m()).unwrap(), vec![]);
        let e = ByteStream::wrap(vec![10]).apply(m()).unwrap_err();
        assert_eq!(e.to_string(), "at offset 0: too long");
    }

    #[test]
    fn boxed_is_resumable() {
        let m = before(';').then(exact(b";")).map(|(v, _)| v).boxed();
        assert_eq!(feed(m, b"abcdef;", 2, false).unwrap(), b"abcdef");
    }

    // Results must not depend on how the input is split into chunks.
    #[test]
    fn chunk_invariance() {
        type Items = Vec<(Vec<u8>, Option<char>)>;
        fn grammar() -> impl Matcher<(Items, Vec<u8>)> {
            let item = take_while(|b| b.is_ascii_digit())
                .then(maybe(single('+')))
                .then(exact(b","));
            repeat(item.map(|(t, _)| t))
                .then(maybe(exact(b"!")))
                .map(|(items, _)| items)
                .then(exact(b";"))
        }
        fn f(data: Vec<u8>, chunk: u8, close: bool) -> bool {
            let data: Vec<u8> = data.iter().map(|b| b"0123+,;!x"[*b as usize % 9]).collect();
            let mut whole = if close {
                ByteStream::wrap(data.clone())
            } else {
                open(&data)
            };
            let expected = whole.apply(grammar());
            let actual = feed(grammar(), &data, chunk as usize % 8 + 1, close);
            match (&expected, &actual) {
                (Ok(a), Ok(b)) => a == b,
                (Err(a), Err(b)) => a.kind() == b.kind(),
                _ => false,
            }
        }
        quickcheck::QuickCheck::new()
            .tests(5_000)
            .quickcheck(f as fn(Vec<u8>, u8, bool) -> bool);
    }

    #[test]
    fn zero_copy_spans() {
        let input = b"key=value;tail";
        let m = || {
            recognize(skip_while1(|b| b != b'=', "key"))
                .then(tag(b"="))
                .then(recognize(skip_while(|b| b != b';')))
                .map(|((k, _), v)| (k, v))
        };
        let mut bs = ByteStream::borrow(input);
        let (k, v) = bs.apply(m()).unwrap();
        assert_eq!(
            (&input[k.clone()], &input[v.clone()]),
            (&b"key"[..], &b"value"[..])
        );
        assert_eq!(bs.slice(k), Some(&b"key"[..]));

        // spans are stream offsets: they stay valid across pulls and resumes
        for chunk in 1..6 {
            let (k, v) = feed(m(), input, chunk, false).unwrap();
            assert_eq!((k, v), (0..3, 4..9), "chunk={}", chunk);
        }
        assert!(
            ByteStream::borrow(b"=x;")
                .apply(m())
                .unwrap_err()
                .to_string()
                .contains("expected key")
        );
    }

    #[test]
    fn advance_and_rest() {
        let mut bs = ByteStream::borrow(b"0123456789");
        assert_eq!(bs.apply(recognize(advance(4))).unwrap(), 0..4);
        assert!(bs.apply(advance(7)).unwrap_err().is_incomplete());
        assert_eq!(bs.apply(rest()).unwrap(), b"456789");
        assert_eq!(
            feed(recognize(advance(300)), &[0; 300], 7, false).unwrap(),
            0..300
        );
        assert!(
            ByteStream::partial(b"abc")
                .apply(rest())
                .unwrap_err()
                .is_incomplete()
        );
    }

    #[test]
    fn limit_restricts_what_inner_matcher_sees() {
        // without the window, take_while would copy the whole megabyte first
        let big = vec![b'a'; 1 << 20];
        let mut bs = ByteStream::borrow(&big);
        let e = bs.apply(limit(10, take_while(|b| b == b'a'))).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TooLarge);
        assert_eq!(e.offset(), 0);
        assert_eq!(bs.pos(), 0);

        // an atomic matcher needing more than the limit allows
        let mut bs = ByteStream::borrow(b"abcdef");
        let e = bs.apply(limit(3, tag(b"abcdef"))).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TooLarge);

        // closed stream within the limit: end of input is still end of input
        let mut bs = ByteStream::borrow(b"aaa");
        assert_eq!(
            bs.apply(limit(10, take_while(|b| b == b'a'))).unwrap(),
            b"aaa"
        );
        let mut bs = ByteStream::borrow(b"aaa");
        assert_eq!(
            bs.apply(limit(3, take_while(|b| b == b'a'))).unwrap(),
            b"aaa"
        );
        // nested limits
        let mut bs = ByteStream::borrow(b"aaaa;");
        let m = limit(10, limit(2, take_while(|b| b == b'a')));
        assert_eq!(bs.apply(m).unwrap_err().kind(), ErrorKind::TooLarge);
    }

    #[test]
    fn test_or() {
        let m = || {
            tag(b"ab")
                .map(|_| 1)
                .or(tag(b"ac").map(|_| 2))
                .or(one(b'a').map(|_| 3))
        };
        let ok = |input: &[u8]| ByteStream::borrow(input).apply(m());
        let bool = tag(b"yes").or(tag(b"no")).or(tag(b"maybe"));
        let e = ByteStream::borrow(b"x").apply(bool).unwrap_err();
        assert_eq!(
            e.to_string(),
            "at offset 0: expected 'y' or 'n' or 'm' but found 'x'"
        );
        assert_eq!(ok(b"ab"), Ok(1));
        assert_eq!(ok(b"ac"), Ok(2));
        assert_eq!(ok(b"ax"), Ok(3));
        assert!(ok(b"x").is_err());
        // closed stream: a prefix of the first branch can't match it, so the others are tried
        assert_eq!(ok(b"a"), Ok(3));
        // open stream: the first branch may still match, so wait
        assert!(
            ByteStream::partial(b"a")
                .apply(m())
                .unwrap_err()
                .is_incomplete()
        );
        for chunk in 1..3 {
            assert_eq!(feed(m(), b"ac", chunk, false), Ok(2));
        }

        // committed once the first branch consumed input
        let m = tag(b"a")
            .then(tag(b"b"))
            .map(|_| 1)
            .or(tag(b"ac").map(|_| 2));
        let e = ByteStream::borrow(b"ac").apply(m).unwrap_err();
        assert_eq!(e.offset(), 1);
        let m = attempt(tag(b"a").then(tag(b"b")))
            .map(|_| 1)
            .or(tag(b"ac").map(|_| 2));
        assert_eq!(ByteStream::borrow(b"ac").apply(m), Ok(2));
    }

    #[test]
    fn sequencing_helpers() {
        let mut bs = ByteStream::borrow(b"(42)!");
        assert_eq!(bs.apply(delimited(tag(b"("), decimal(), tag(b")"))), Ok(42));
        assert_eq!(bs.apply(tag(b"!").ignore()), Ok(()));
        let mut bs = ByteStream::borrow(b"x=1;");
        let m = terminated(preceded(tag(b"x="), decimal()), tag(b";"));
        assert_eq!(bs.apply(m), Ok(1));
        assert_eq!(
            ByteStream::borrow(b"ab").apply(one(b'a').ignore_then(one(b'b'))),
            Ok(b'b')
        );
        assert_eq!(
            ByteStream::borrow(b"ab").apply(one(b'a').then_ignore(one(b'b'))),
            Ok(b'a')
        );
    }

    #[test]
    fn test_separated() {
        let list = || separated(decimal(), tag(b", "));
        let parse = |input: &[u8]| ByteStream::borrow(input).apply(list());
        assert_eq!(parse(b""), Ok(vec![]));
        assert_eq!(parse(b"7"), Ok(vec![7]));
        assert_eq!(parse(b"1, 2, 3;"), Ok(vec![1, 2, 3]));
        // a separator must be followed by an item
        assert!(parse(b"1, 2, ").is_err());
        assert!(parse(b"1, x").is_err());
        // a partial separator on an open stream
        assert!(
            ByteStream::partial(b"1,")
                .apply(list())
                .unwrap_err()
                .is_incomplete()
        );
        for chunk in 1..5 {
            assert_eq!(
                feed(list(), b"10, 200, 3000", chunk, true),
                Ok(vec![10, 200, 3000])
            );
        }
    }

    #[test]
    fn memchr_and_find() {
        fn check(hay: &[u8], needle: &[u8]) {
            let expected = if needle.is_empty() {
                Some(0)
            } else {
                hay.windows(needle.len()).position(|w| w == needle)
            };
            assert_eq!(find(hay, needle), expected, "{:?} in {:?}", needle, hay);
        }
        let hay: Vec<u8> = (0..100u8).map(|i| i % 7).collect();
        for len in 0..hay.len() {
            for b in 0..8u8 {
                assert_eq!(
                    memchr(b, &hay[len..]),
                    hay[len..].iter().position(|x| *x == b)
                );
                check(&hay[len..], &[b]);
                check(&hay[len..], &[b, (b + 1) % 7]);
                check(&hay[len..], &[b, (b + 1) % 7, (b + 2) % 7]);
            }
        }
        check(b"aaaab", b"aab");
        check(b"ab", b"abc");
        check(b"", b"");
        assert_eq!(
            memchr(0x80, &[0x7F, 0x80, 0x81, 0, 0, 0, 0, 0, 0x80]),
            Some(1)
        );
        assert_eq!(memchr(0, &[1, 1, 1, 1, 1, 1, 1, 0xFF, 0]), Some(8));
    }

    #[test]
    fn test_take_until() {
        let line = || take_until(b"\r\n").then_ignore(tag(b"\r\n"));
        assert_eq!(
            ByteStream::borrow(b"abc\r\nx").apply(line()),
            Ok(b"abc".to_vec())
        );
        assert_eq!(ByteStream::borrow(b"\r\n").apply(line()), Ok(vec![]));
        assert!(
            ByteStream::borrow(b"abc\r")
                .apply(line())
                .unwrap_err()
                .is_incomplete()
        );
        // the pattern split across chunks, and output larger than the buffer
        let long = [vec![b'x'; 300], b"\r\n".to_vec()].concat();
        for chunk in 1..8 {
            assert_eq!(feed(line(), b"ab\r\n", chunk, false), Ok(b"ab".to_vec()));
            assert_eq!(feed(line(), &long, chunk, false).unwrap().len(), 300);
            assert_eq!(
                feed(recognize(skip_until(b"\r\n")), &long, chunk, false),
                Ok(0..300)
            );
        }
    }

    #[test]
    fn test_sized() {
        let frame = || length_prefixed(get_u8(), || separated(decimal(), tag(b",")));
        let parse = |input: &[u8]| ByteStream::borrow(input).apply(frame());
        assert_eq!(parse(b"\x031,2rest"), Ok(vec![1, 2]));
        // `decimal` sees the end of the frame as the end of input
        assert_eq!(parse(b"\x0212345"), Ok(vec![12]));
        assert_eq!(parse(b"\x00"), Ok(vec![]));
        let e = parse(b"\x031,x").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unexpected);
        let e = ByteStream::borrow(b"\x03ab")
            .apply(length_prefixed(get_u8(), || tag(b"ab")))
            .unwrap_err();
        assert!(e.to_string().contains("unconsumed bytes"), "{}", e);
        let e = ByteStream::borrow(b"\x01ab")
            .apply(length_prefixed(get_u8(), || tag(b"ab")))
            .unwrap_err();
        assert!(e.to_string().contains("frame too short"), "{}", e);
        // truncated frame on an open stream: wait for it
        assert!(
            ByteStream::partial(b"\x031,")
                .apply(frame())
                .unwrap_err()
                .is_incomplete()
        );
        // larger than the buffer, resumed
        let big = [&[200u8][..], &[b'7'; 200]].concat();
        let digits = || length_prefixed(get_u8(), || take_while(|b| b.is_ascii_digit()));
        for chunk in 1..8 {
            assert_eq!(
                feed(frame(), b"\x051,2,3tail", chunk, false),
                Ok(vec![1, 2, 3])
            );
            assert_eq!(feed(digits(), &big, chunk, false).unwrap().len(), 200);
        }
        // a nested limit is still respected inside a frame
        let m = length_prefixed(get_u8(), || limit(2, rest()));
        assert_eq!(
            ByteStream::borrow(b"\x03abc").apply(m).unwrap_err().kind(),
            ErrorKind::TooLarge
        );
    }

    #[test]
    fn lookahead() {
        let mut bs = ByteStream::borrow(b"ab");
        assert_eq!(bs.apply(peek(tag(b"ab"))), Ok(()));
        assert_eq!(bs.pos(), 0);
        assert!(bs.apply(not(tag(b"ab"))).is_err());
        assert_eq!(bs.apply(not(tag(b"x"))), Ok(()));
        assert!(bs.apply(eof()).is_err());
        bs.skip(2);
        assert_eq!(bs.apply(eof()), Ok(()));
        assert!(
            ByteStream::partial(b"")
                .apply(eof())
                .unwrap_err()
                .is_incomplete()
        );
        assert!(
            ByteStream::partial(b"a")
                .apply(not(tag(b"ab")))
                .unwrap_err()
                .is_incomplete()
        );
    }

    #[test]
    fn numbers() {
        let mut bs = ByteStream::borrow(&[1, 2, 1, 2, 3, 4, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(bs.apply(get_u16_le()), Ok(0x0201));
        assert_eq!(bs.apply(get_u32_le()), Ok(0x04030201));
        assert_eq!(bs.apply(get_u64_le()), Ok(1));
        assert!(bs.apply(get_u16_le()).unwrap_err().is_incomplete());

        let v = |input: &[u8]| ByteStream::borrow(input).apply(varint());
        assert_eq!(v(&[0]), Ok(0));
        assert_eq!(v(&[0x7F]), Ok(127));
        assert_eq!(v(&[0x80, 0x01]), Ok(128));
        assert_eq!(
            v(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]),
            Ok(u64::MAX)
        );
        assert!(v(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]).is_err());
        assert!(v(&[0x80; 11]).is_err());
        assert!(v(&[0x80, 0x80]).unwrap_err().is_incomplete());
        for chunk in 1..4 {
            assert_eq!(feed(varint(), &[0xAC, 0x02], chunk, false), Ok(300));
        }

        let d = |input: &[u8]| ByteStream::borrow(input).apply(decimal());
        assert_eq!(d(b"0"), Ok(0));
        assert_eq!(d(b"18446744073709551615"), Ok(u64::MAX));
        assert!(d(b"18446744073709551616").is_err());
        assert!(d(b"x").is_err());
        assert!(d(b"").unwrap_err().is_incomplete());
        assert!(
            ByteStream::partial(b"12")
                .apply(decimal())
                .unwrap_err()
                .is_incomplete()
        );
        for chunk in 1..4 {
            assert_eq!(feed(decimal(), b"12345;", chunk, false), Ok(12345));
        }
        let i = |input: &[u8]| ByteStream::borrow(input).apply(integer());
        assert_eq!(i(b"-9223372036854775808"), Ok(i64::MIN));
        assert_eq!(i(b"9223372036854775807"), Ok(i64::MAX));
        assert!(i(b"9223372036854775808").is_err());
        assert!(i(b"-9223372036854775809").is_err());
        assert_eq!(i(b"-0"), Ok(0));
        assert!(i(b"-").is_err());
    }

    #[test]
    fn full_buffer_is_an_error_not_a_hang() {
        // an atomic step larger than the buffer can never complete
        let mut bs = ByteStream::with_capacity(4);
        bs.put(b"abcd");
        let e = bs.apply(tag(b"abcdef")).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TooLarge);
        assert!(
            e.to_string()
                .contains("does not fit into the buffer of 4 bytes"),
            "{}",
            e
        );
        let mut parser = Resumable::new(tag(b"abcdef"));
        assert_eq!(
            parser.parse(&mut bs).unwrap_err().kind(),
            ErrorKind::TooLarge
        );

        // not stuck: consumed bytes can be pulled, or there is room left
        let mut bs = ByteStream::with_capacity(4);
        bs.put(b"xabc");
        bs.skip(1);
        assert!(bs.apply(tag(b"abcd")).unwrap_err().is_incomplete());
        let mut bs = ByteStream::with_capacity(8);
        bs.put(b"abcd");
        assert!(bs.apply(tag(b"abcdef")).unwrap_err().is_incomplete());
        // accumulating matchers never get stuck
        let mut parser = Resumable::new(bytes(10));
        let mut bs = ByteStream::with_capacity(4);
        bs.put(b"abcd");
        assert!(parser.parse(&mut bs).unwrap_err().is_incomplete());
    }

    #[test]
    fn growable_buffer_and_read_from() {
        let mut bs = ByteStream::growable(2, 6);
        assert_eq!(bs.put(b"abcd"), 4, "grows beyond the initial capacity");
        assert_eq!(bs.put(b"efg"), 0, "but not beyond the maximum");
        assert_eq!(bs.put_some(b"efg"), 2);
        assert_eq!(bs.as_ref(), b"abcdef");
        assert!(bs.is_full());

        let input = b"hello, world".to_vec();
        let mut reader = &input[..];
        let mut bs = ByteStream::with_capacity(5);
        let mut out = Vec::new();
        loop {
            bs.pull();
            if bs.read_from(&mut reader).unwrap() == 0 {
                break;
            }
            out.extend_from_slice(bs.take(bs.remaining()).unwrap());
        }
        assert_eq!(out, input);
        assert!(bs.is_closed());
        let mut full = ByteStream::with_capacity(1);
        full.put(b"x");
        assert_eq!(
            full.read_from(&mut &b"y"[..]).unwrap_err().kind(),
            std::io::ErrorKind::OutOfMemory
        );
    }

    // Results must not depend on how the input is split into chunks, for a grammar
    // using most of the combinators.
    #[test]
    fn chunk_invariance_all_combinators() {
        #[derive(Debug, PartialEq)]
        enum Item {
            Num(u64),
            Line(Vec<u8>),
            Frame(Vec<i64>),
            Var(u64),
        }
        fn grammar() -> impl Matcher<Vec<Item>> {
            let num = preceded(tag(b"n"), decimal()).map(Item::Num);
            let line = delimited(tag(b"l"), take_until(b";;"), tag(b";;")).map(Item::Line);
            let frame = preceded(
                tag(b"f"),
                length_prefixed(get_u8(), || separated(integer(), tag(b","))),
            )
            .map(Item::Frame);
            let var = preceded(tag(b"v"), varint()).map(Item::Var);
            separated(num.or(line).or(frame).or(var), tag(b" ")).then_ignore(eof())
        }
        fn f(data: Vec<u8>, chunk: u8, close: bool) -> bool {
            let data: Vec<u8> = data
                .iter()
                .map(|b| b"nlfv 0123-,;\x03\x05\x80\x01"[*b as usize % 16])
                .collect();
            let mut whole = if close {
                ByteStream::borrow(&data)
            } else {
                ByteStream::partial(&data)
            };
            let expected = whole.apply(grammar());
            let actual = feed(grammar(), &data, chunk as usize % 8 + 1, close);
            match (&expected, &actual) {
                (Ok(a), Ok(b)) => a == b,
                (Err(a), Err(b)) => a.kind() == b.kind(),
                _ => false,
            }
        }
        quickcheck::QuickCheck::new()
            .tests(10_000)
            .quickcheck(f as fn(Vec<u8>, u8, bool) -> bool);
    }

    // A reader that returns `WouldBlock` before every chunk, like a non-blocking socket.
    struct Nonblocking<'a> {
        data: &'a [u8],
        step: usize,
        ready: bool,
    }

    impl std::io::Read for Nonblocking<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.ready = !self.ready;
            if !self.ready {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let n = self.step.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    fn line() -> impl Matcher<Vec<u8>> {
        take_until(b"\r\n").then_ignore(tag(b"\r\n"))
    }

    #[test]
    fn read_from_driver() {
        use crate::matcher::ReadError;
        // clean end of input
        let mut parser = Resumable::new(line());
        let mut bs = ByteStream::with_capacity(8);
        let mut input = &b"ab\r\ncd\r\n"[..];
        assert_eq!(
            parser.read_from(&mut bs, &mut input).unwrap(),
            Some(b"ab".to_vec())
        );
        assert_eq!(
            parser.read_from(&mut bs, &mut input).unwrap(),
            Some(b"cd".to_vec())
        );
        assert_eq!(parser.read_from(&mut bs, &mut input).unwrap(), None);
        assert_eq!(parser.read_from(&mut bs, &mut input).unwrap(), None);

        // truncated: in the middle of a value, consumed or still buffered
        for input in [&b"ab\r\ncd"[..], b"ab\r\n\r", b"ab\r\nc"] {
            let mut parser = Resumable::new(line());
            let mut bs = ByteStream::with_capacity(8);
            let mut input = input;
            assert!(parser.read_from(&mut bs, &mut input).unwrap().is_some());
            let e = parser.read_from(&mut bs, &mut input).unwrap_err();
            assert!(matches!(e, ReadError::Truncated(_)), "{}", e);
        }

        // non-blocking: WouldBlock keeps the progress
        let data = [&b"a much longer line\r\n"[..], b"x\r\n"].concat();
        let mut reader = Nonblocking {
            data: &data,
            step: 3,
            ready: false,
        };
        let mut parser = Resumable::new(line());
        let mut bs = ByteStream::with_capacity(8);
        let mut got = Vec::new();
        loop {
            match parser.read_from(&mut bs, &mut reader) {
                Ok(Some(v)) => got.push(v),
                Ok(None) => break,
                Err(ReadError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("{}", e),
            }
        }
        assert_eq!(got, vec![b"a much longer line".to_vec(), b"x".to_vec()]);

        // a parse error, then the next value
        let mut parser = Resumable::new(decimal().then_ignore(tag(b";")));
        let mut bs = ByteStream::with_capacity(8);
        let mut input = &b"1;x2;"[..];
        assert_eq!(parser.read_from(&mut bs, &mut input).unwrap(), Some(1));
        assert!(matches!(
            parser.read_from(&mut bs, &mut input),
            Err(ReadError::Parse(_))
        ));
        bs.skip(1);
        assert_eq!(parser.read_from(&mut bs, &mut input).unwrap(), Some(2));

        // an atomic step larger than the buffer: an error, not a hang
        let mut parser = Resumable::new(tag(b"0123456789"));
        let mut bs = ByteStream::with_capacity(4);
        let mut input = &b"0123456789"[..];
        let e = parser.read_from(&mut bs, &mut input).unwrap_err();
        assert!(
            matches!(&e, ReadError::Parse(e) if e.kind() == ErrorKind::TooLarge),
            "{}",
            e
        );

        // a borrowed stream cannot read
        let mut parser = Resumable::new(line());
        let e = parser
            .read_from(&mut ByteStream::partial(b"ab"), &mut &b"\r\n"[..])
            .unwrap_err();
        assert!(matches!(e, ReadError::Io(_)));
    }
}
