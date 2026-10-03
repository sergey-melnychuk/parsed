//! The [`Matcher`] trait, the core combinators built into it, and [`MatchError`].

use crate::stream::ByteStream;
use std::any::Any;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::{error, fmt};

/// A parser that produces a value of type `T` from a [`ByteStream`].
///
/// Matchers are *resumable*: [`Matcher::resume`] keeps the progress of a partially
/// completed match in [`Matcher::State`], so when input runs out
/// ([`ErrorKind::Incomplete`]) the results of completed steps are kept, their bytes
/// stay consumed, and the next call continues at the step that ran out of input.
/// Use [`Resumable`] to drive a matcher over incrementally received input, or
/// [`Matcher::do_match`] (or [`Applicator::apply`](crate::parser::Applicator::apply))
/// for a one-shot match that restarts from scratch.
///
/// Any `Fn(&mut ByteStream) -> Result<T, MatchError>` is a matcher without state: it
/// restarts on every call, so it must not consume input when it fails.
pub trait Matcher<T> {
    /// Progress of a partially completed match, kept between calls to [`Matcher::resume`].
    ///
    /// States are `Send`, so that parsers can be moved between threads and held across
    /// `.await` (values kept in a state, like the first value of [`Matcher::then`] while
    /// the second one is incomplete, must be `Send` too).
    type State: Default + Send;

    /// Continue matching from `state`.
    ///
    /// - `Ok(value)`: the match is complete and `state` is back to its default.
    /// - `Err` with [`ErrorKind::Incomplete`]: input ended. Bytes of the completed steps
    ///   are consumed and accounted for in `state`; call again with the same `state`
    ///   once more bytes are available.
    /// - `Err` with [`ErrorKind::Unexpected`]: input does not match. `state` must be
    ///   reset to its default before it is reused.
    fn resume(&self, state: &mut Self::State, bs: &mut ByteStream<'_>) -> Result<T, MatchError>;

    /// One-shot match with a fresh state. On any error the stream is reset to where
    /// the match started, so a failed match never consumes input.
    ///
    /// `Incomplete` on a stream that [is full](ByteStream::is_full) becomes
    /// [`ErrorKind::TooLarge`]: the match can never complete in that buffer.
    fn do_match(&self, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        let mark = bs.mark();
        let mut state = Self::State::default();
        let result = self.resume(&mut state, bs);
        if result.is_err() {
            bs.reset(mark);
        }
        stuck(result, bs)
    }

    /// Erase the matcher type, e.g. to store it in a struct field. The matcher must be
    /// `Send + Sync` and its state `Send`, so that boxed matchers (and parsers built on
    /// them) can be moved between threads and held across `.await`.
    fn boxed(self) -> Boxed<T>
    where
        Self: Sized + Send + Sync + 'static,
        Self::State: 'static,
    {
        Boxed(Box::new(self))
    }

    /// Match `self`, then `that`, producing both values.
    fn then<U, That>(self, that: That) -> Chain<Self, That>
    where
        Self: Sized,
        That: Matcher<U>,
    {
        Chain(self, that)
    }

    /// Match `self`, then the matcher built by `f` from the value of `self`,
    /// producing both values (context-sensitive parsing, e.g. length-prefixed data).
    fn then_with<U, F, N>(self, f: F) -> Expose<Self, F>
    where
        Self: Sized,
        F: Fn(&T) -> N,
        N: Matcher<U>,
    {
        Expose {
            context: self,
            next: f,
        }
    }

    /// Transform the matched value.
    fn map<U, F>(self, f: F) -> Map<Self, T, F>
    where
        Self: Sized,
        F: Fn(T) -> U,
    {
        Map {
            prev: self,
            mapper: f,
            phantom: PhantomData,
        }
    }

    /// Shorthand for `self.then(that).map(f)`.
    fn then_map<U, That, F, V>(self, that: That, f: F) -> Map<Chain<Self, That>, (T, U), F>
    where
        Self: Sized,
        T: Send,
        That: Matcher<U>,
        F: Fn((T, U)) -> V,
    {
        self.then(that).map(f)
    }

    /// Transform the matched value with a function that may reject it: an `Err(message)`
    /// becomes an [`ErrorKind::Unexpected`] error.
    fn try_map<U, E, F>(self, f: F) -> TryMap<Self, T, F>
    where
        Self: Sized,
        E: Into<Cow<'static, str>>,
        F: Fn(T) -> Result<U, E>,
    {
        TryMap {
            prev: self,
            mapper: f,
            phantom: PhantomData,
        }
    }

    /// Match `self`, or else `other`: `other` is tried if `self` fails without
    /// consuming input (like [`maybe`](crate::parser::maybe), `self` is committed to
    /// once it consumed input; wrap it in [`attempt`](crate::parser::attempt) to
    /// backtrack further).
    ///
    /// ```
    /// use parsed::parser::{tag, Applicator, Matcher};
    /// use parsed::stream::ByteStream;
    ///
    /// let bool = tag(b"true").map(|_| true).or(tag(b"false").map(|_| false));
    /// assert_eq!(ByteStream::borrow(b"false").apply(bool), Ok(false));
    /// ```
    fn or<That>(self, other: That) -> Or<Self, That>
    where
        Self: Sized,
        That: Matcher<T>,
    {
        Or(self, other)
    }

    /// Match `self`, then `that`, producing the value of `self`.
    fn then_ignore<U, That>(self, that: That) -> ThenIgnore<Self, That, T, U>
    where
        Self: Sized,
        T: Send,
        That: Matcher<U>,
    {
        self.then(that).map(|(t, _)| t)
    }

    /// Match `self`, then `that`, producing the value of `that`.
    fn ignore_then<U, That>(self, that: That) -> IgnoreThen<Self, That, T, U>
    where
        Self: Sized,
        T: Send,
        That: Matcher<U>,
    {
        self.then(that).map(|(_, u)| u)
    }

    /// Drop the matched value.
    fn ignore(self) -> Map<Self, T, fn(T)>
    where
        Self: Sized,
    {
        self.map(|_| ())
    }

    /// Label errors of this matcher (unless labelled by an inner matcher already),
    /// see [`MatchError::context`].
    fn context(self, context: &'static str) -> Context<Self>
    where
        Self: Sized,
    {
        Context {
            inner: self,
            context,
        }
    }

    /// Like [`Matcher::try_map`], with access to the stream, e.g. to look at the bytes of
    /// spans produced by [`recognize`](crate::parser::recognize).
    fn try_map_with<U, E, F>(self, f: F) -> TryMapWith<Self, T, F>
    where
        Self: Sized,
        E: Into<Cow<'static, str>>,
        F: Fn(T, &ByteStream<'_>) -> Result<U, E>,
    {
        TryMapWith {
            prev: self,
            mapper: f,
            phantom: PhantomData,
        }
    }
}

/// Matcher returned by [`Matcher::or`].
pub struct Or<A, B>(A, B);

/// State of [`Or`].
pub struct OrState<A, B> {
    branch: OrBranch<A, B>,
    // the first branch has consumed input, so it is committed
    consumed: bool,
}

enum OrBranch<A, B> {
    First(A),
    Second(B),
}

impl<A: Default, B> Default for OrState<A, B> {
    fn default() -> Self {
        OrState {
            branch: OrBranch::First(A::default()),
            consumed: false,
        }
    }
}

impl<A: Matcher<T>, B: Matcher<T>, T> Matcher<T> for Or<A, B> {
    type State = OrState<A::State, B::State>;

    fn resume(&self, state: &mut Self::State, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        if let OrBranch::First(first) = &mut state.branch {
            let pos = bs.pos();
            let result = self.0.resume(first, bs);
            state.consumed |= bs.pos() != pos;
            match result {
                Ok(t) => {
                    *state = OrState::default();
                    return Ok(t);
                }
                // more input may still make the first branch match
                Err(e) if e.is_incomplete() && (state.consumed || !bs.is_closed()) => {
                    return Err(e);
                }
                Err(e) if state.consumed => {
                    *state = OrState::default();
                    return Err(e);
                }
                // failed without consuming input: try the other branch
                Err(e) => {
                    state.branch = OrBranch::Second(B::State::default());
                    let OrBranch::Second(second) = &mut state.branch else {
                        unreachable!()
                    };
                    let result = self.1.resume(second, bs);
                    if !matches!(&result, Err(e) if e.is_incomplete()) {
                        *state = OrState::default();
                    }
                    return result.map_err(|other| e.or_expected(other));
                }
            }
        }
        let OrBranch::Second(second) = &mut state.branch else {
            unreachable!()
        };
        let result = self.1.resume(second, bs);
        if !matches!(&result, Err(e) if e.is_incomplete()) {
            *state = OrState::default();
        }
        result
    }
}

/// Matcher returned by [`Matcher::context`].
pub struct Context<M> {
    inner: M,
    context: &'static str,
}

impl<M: Matcher<T>, T> Matcher<T> for Context<M> {
    type State = M::State;

    fn resume(&self, state: &mut M::State, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        self.inner
            .resume(state, bs)
            .map_err(|e| e.with_context(self.context))
    }
}

/// Matcher returned by [`Matcher::try_map_with`].
pub struct TryMapWith<M, T, F> {
    prev: M,
    mapper: F,
    phantom: PhantomData<fn() -> T>,
}

impl<M, T, U, E, F> Matcher<U> for TryMapWith<M, T, F>
where
    M: Matcher<T>,
    E: Into<Cow<'static, str>>,
    F: Fn(T, &ByteStream<'_>) -> Result<U, E>,
{
    type State = StartState<M::State>;

    fn resume(&self, state: &mut Self::State, bs: &mut ByteStream<'_>) -> Result<U, MatchError> {
        let (t, start) = state.resume(&self.prev, bs)?;
        (self.mapper)(t, bs).map_err(|e| MatchError::invalid(start, e))
    }
}

impl<T, F> Matcher<T> for F
where
    F: Fn(&mut ByteStream<'_>) -> Result<T, MatchError>,
{
    type State = ();

    fn resume(&self, _: &mut (), bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        (self)(bs)
    }
}

/// Matcher returned by [`Matcher::then_ignore`].
pub type ThenIgnore<A, B, T, U> = Map<Chain<A, B>, (T, U), fn((T, U)) -> T>;

/// Matcher returned by [`Matcher::ignore_then`].
pub type IgnoreThen<A, B, T, U> = Map<Chain<A, B>, (T, U), fn((T, U)) -> U>;

/// Matcher returned by [`Matcher::then`].
pub struct Chain<M, N>(M, N);

// States of `Chain` and `Expose` keep the sub-states side by side and move only the
// intermediate value: a sub-state is back to its default once its matcher succeeds, so
// nothing needs to be reset (and a deeply nested state is never moved as a whole).

/// State of [`Chain`].
pub struct ChainState<A, T, B> {
    first: A,
    value: Option<T>,
    second: B,
}

impl<A: Default, T, B: Default> Default for ChainState<A, T, B> {
    fn default() -> Self {
        ChainState {
            first: A::default(),
            value: None,
            second: B::default(),
        }
    }
}

impl<M, N, T, U> Matcher<(T, U)> for Chain<M, N>
where
    T: Send,
    M: Matcher<T>,
    N: Matcher<U>,
{
    type State = ChainState<M::State, T, N::State>;

    fn resume(
        &self,
        state: &mut Self::State,
        bs: &mut ByteStream<'_>,
    ) -> Result<(T, U), MatchError> {
        if state.value.is_none() {
            state.value = Some(self.0.resume(&mut state.first, bs)?);
        }
        let u = self.1.resume(&mut state.second, bs)?;
        let t = state.value.take().expect("first value is set");
        Ok((t, u))
    }
}

/// Matcher returned by [`Matcher::then_with`].
pub struct Expose<M, F> {
    context: M,
    next: F,
}

/// State of [`Expose`].
pub struct ExposeState<A, T, N, B> {
    first: A,
    value: Option<(T, N)>,
    second: B,
}

impl<A: Default, T, N, B: Default> Default for ExposeState<A, T, N, B> {
    fn default() -> Self {
        ExposeState {
            first: A::default(),
            value: None,
            second: B::default(),
        }
    }
}

impl<M, F, N, T, U> Matcher<(T, U)> for Expose<M, F>
where
    T: Send,
    N: Send,
    M: Matcher<T>,
    F: Fn(&T) -> N,
    N: Matcher<U>,
{
    type State = ExposeState<M::State, T, N, N::State>;

    fn resume(
        &self,
        state: &mut Self::State,
        bs: &mut ByteStream<'_>,
    ) -> Result<(T, U), MatchError> {
        if state.value.is_none() {
            let t = self.context.resume(&mut state.first, bs)?;
            let next = (self.next)(&t);
            state.value = Some((t, next));
        }
        let (_, next) = state.value.as_ref().expect("first value is set");
        let u = next.resume(&mut state.second, bs)?;
        let (t, _) = state.value.take().expect("first value is set");
        Ok((t, u))
    }
}

/// Matcher returned by [`Matcher::map`].
pub struct Map<M, T, F> {
    prev: M,
    mapper: F,
    phantom: PhantomData<fn() -> T>,
}

impl<M, T, U, F> Matcher<U> for Map<M, T, F>
where
    M: Matcher<T>,
    F: Fn(T) -> U,
{
    type State = M::State;

    fn resume(&self, state: &mut M::State, bs: &mut ByteStream<'_>) -> Result<U, MatchError> {
        self.prev.resume(state, bs).map(&self.mapper)
    }
}

/// State of a matcher remembering the stream offset where its match started.
#[derive(Default)]
pub struct StartState<S> {
    start: Option<usize>,
    inner: S,
}

impl<S> StartState<S> {
    pub(crate) fn resume<T, M: Matcher<T, State = S>>(
        &mut self,
        m: &M,
        bs: &mut ByteStream<'_>,
    ) -> Result<(T, usize), MatchError> {
        let start = *self.start.get_or_insert(bs.offset());
        let t = m.resume(&mut self.inner, bs)?;
        self.start = None;
        Ok((t, start))
    }
}

/// Matcher returned by [`Matcher::try_map`].
pub struct TryMap<M, T, F> {
    prev: M,
    mapper: F,
    phantom: PhantomData<fn() -> T>,
}

impl<M, T, U, E, F> Matcher<U> for TryMap<M, T, F>
where
    M: Matcher<T>,
    E: Into<Cow<'static, str>>,
    F: Fn(T) -> Result<U, E>,
{
    type State = StartState<M::State>;

    fn resume(&self, state: &mut Self::State, bs: &mut ByteStream<'_>) -> Result<U, MatchError> {
        let (t, start) = state.resume(&self.prev, bs)?;
        (self.mapper)(t).map_err(|e| MatchError::invalid(start, e))
    }
}

/// Type-erased matcher returned by [`Matcher::boxed`].
pub struct Boxed<T>(Box<dyn DynMatcher<T> + Send + Sync>);

/// State of [`Boxed`].
#[derive(Default)]
pub struct BoxedState(Option<Box<dyn Any + Send>>);

trait DynMatcher<T> {
    fn resume_dyn(
        &self,
        state: &mut Option<Box<dyn Any + Send>>,
        bs: &mut ByteStream,
    ) -> Result<T, MatchError>;
}

impl<T, M> DynMatcher<T> for M
where
    M: Matcher<T>,
    M::State: 'static,
{
    fn resume_dyn(
        &self,
        state: &mut Option<Box<dyn Any + Send>>,
        bs: &mut ByteStream,
    ) -> Result<T, MatchError> {
        let any = state.get_or_insert_with(|| Box::new(M::State::default()));
        let typed = (**any)
            .downcast_mut::<M::State>()
            .expect("state of a boxed matcher has the matcher's state type");
        let result = self.resume(typed, bs);
        if matches!(&result, Err(e) if !e.is_incomplete()) {
            *state = None;
        }
        result
    }
}

impl<T> Matcher<T> for Boxed<T> {
    type State = BoxedState;

    fn resume(&self, state: &mut BoxedState, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        self.0.resume_dyn(&mut state.0, bs)
    }
}

/// A matcher together with the state of its current (possibly partial) match:
/// the driver for parsing incrementally received input.
///
/// ```
/// use parsed::matcher::Resumable;
/// use parsed::parser::{before, exact, Matcher};
/// use parsed::stream::ByteStream;
///
/// let mut line = Resumable::new(before('\n').then(exact(b"\n")).map(|(line, _)| line));
/// let mut bs = ByteStream::with_capacity(16);
///
/// bs.put(b"hello, ");
/// assert!(line.parse(&mut bs).unwrap_err().is_incomplete());
/// bs.pull(); // consumed bytes are kept in the parser state and can be dropped
///
/// bs.put(b"world\n");
/// assert_eq!(line.parse(&mut bs).unwrap(), b"hello, world");
/// ```
pub struct Resumable<M: Matcher<T>, T> {
    matcher: M,
    state: M::State,
    // whether the current match has consumed input
    started: bool,
    phantom: PhantomData<fn() -> T>,
}

impl<M: Matcher<T>, T> Resumable<M, T> {
    /// Wrap a matcher, starting with an empty state.
    pub fn new(matcher: M) -> Self {
        Resumable {
            matcher,
            state: M::State::default(),
            started: false,
            phantom: PhantomData,
        }
    }

    /// Continue the current match. After an [`ErrorKind::Incomplete`] error call again
    /// once more bytes are available. After a successful match or an
    /// [`ErrorKind::Unexpected`] error the next call starts a new match.
    ///
    /// `Incomplete` on a stream that [is full](ByteStream::is_full) becomes
    /// [`ErrorKind::TooLarge`]: the parser needs more contiguous input than the buffer
    /// can hold (a step that matches all or nothing, like [`tag`](crate::parser::tag),
    /// needs its whole input buffered at once).
    ///
    /// See [`Resumable::read_from`] for a loop that also reads the input.
    pub fn parse(&mut self, bs: &mut ByteStream<'_>) -> Result<T, MatchError> {
        let start = bs.offset();
        let result = stuck(self.matcher.resume(&mut self.state, bs), bs);
        self.started |= bs.offset() != start;
        match &result {
            // after a success the state is already back to its default
            Ok(_) => self.started = false,
            Err(e) if !e.is_incomplete() => self.reset(),
            Err(_) => {}
        }
        result
    }

    /// Parse the next value, reading from `reader` into `bs` whenever more input is
    /// needed: the loop around [`Resumable::parse`], [`ByteStream::pull`] and
    /// [`ByteStream::read_from`] that incremental parsing takes.
    ///
    /// - `Ok(Some(value))`: the next value; bytes after it stay buffered for the next call.
    /// - `Ok(None)`: the input ended cleanly, between values.
    /// - `Err(ReadError::Truncated(_))`: the input ended in the middle of a value.
    /// - `Err(ReadError::Parse(_))`: invalid input (the next call starts a new match).
    /// - `Err(ReadError::Io(_))`: reading failed. The progress is kept, so with a
    ///   non-blocking reader, call again on [`WouldBlock`](std::io::ErrorKind::WouldBlock)
    ///   once it is readable.
    ///
    /// `bs` must be an owned stream ([`ByteStream::with_capacity`] or
    /// [`ByteStream::growable`]); consumed bytes are dropped from it before each read.
    ///
    /// ```
    /// use parsed::matcher::Resumable;
    /// use parsed::parser::{tag, take_until, Matcher};
    /// use parsed::stream::ByteStream;
    ///
    /// let mut lines = Resumable::new(take_until(b"\n").then_ignore(tag(b"\n")));
    /// let mut input = &b"one\ntwo\n"[..];
    /// let mut bs = ByteStream::with_capacity(4);
    /// assert_eq!(lines.read_from(&mut bs, &mut input).unwrap(), Some(b"one".to_vec()));
    /// assert_eq!(lines.read_from(&mut bs, &mut input).unwrap(), Some(b"two".to_vec()));
    /// assert_eq!(lines.read_from(&mut bs, &mut input).unwrap(), None);
    /// ```
    pub fn read_from<R: std::io::Read>(
        &mut self,
        bs: &mut ByteStream<'_>,
        reader: &mut R,
    ) -> Result<Option<T>, ReadError> {
        loop {
            match self.parse(bs) {
                Ok(value) => return Ok(Some(value)),
                Err(e) if e.is_incomplete() && bs.is_closed() => {
                    if !self.started && bs.remaining() == 0 {
                        return Ok(None);
                    }
                    self.reset();
                    return Err(ReadError::Truncated(e));
                }
                Err(e) if e.is_incomplete() => {
                    bs.pull();
                    bs.read_from(reader).map_err(ReadError::Io)?;
                }
                Err(e) => return Err(ReadError::Parse(e)),
            }
        }
    }

    /// Drop the progress of the current match.
    pub fn reset(&mut self) {
        self.state = M::State::default();
        self.started = false;
    }

    /// Whether the current match has consumed input (so the end of input now would
    /// truncate it).
    pub fn is_started(&self) -> bool {
        self.started
    }
}

/// Error of [`Resumable::read_from`] (and of the `read_from` of parsers with their own
/// error type `E`, like [`MessageReader`](crate::ws::MessageReader)).
#[derive(Debug)]
pub enum ReadError<E = MatchError> {
    /// Reading the input failed.
    Io(std::io::Error),
    /// The input is invalid.
    Parse(E),
    /// The input ended in the middle of a value.
    Truncated(E),
}

impl<E: fmt::Display> fmt::Display for ReadError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "read error: {}", e),
            ReadError::Parse(e) => write!(f, "{}", e),
            ReadError::Truncated(e) => write!(f, "input truncated {}", e),
        }
    }
}

impl<E: error::Error + 'static> error::Error for ReadError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ReadError::Io(e) => Some(e),
            ReadError::Parse(e) | ReadError::Truncated(e) => Some(e),
        }
    }
}

impl<E> From<std::io::Error> for ReadError<E> {
    fn from(e: std::io::Error) -> Self {
        ReadError::Io(e)
    }
}

fn stuck<T>(result: Result<T, MatchError>, bs: &ByteStream<'_>) -> Result<T, MatchError> {
    match result {
        Err(e) if e.is_incomplete() && bs.is_full() => Err(MatchError::too_large(
            e.offset(),
            format!("input does not fit into the buffer of {} bytes", bs.len()),
        )
        .with_context_of(&e)),
        result => result,
    }
}

/// Matcher that always succeeds without consuming input, producing `f()`.
pub fn unit<T, F: Fn() -> T>(f: F) -> impl Matcher<T> {
    move |_: &mut ByteStream<'_>| Ok(f())
}

/// Broad category of a [`MatchError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Input does not match: retrying with more bytes won't help.
    Unexpected,
    /// Input exceeds a size limit (see [`limit`](crate::parser::limit)).
    TooLarge,
    /// Input ended before a match could be completed: retry when more bytes arrive.
    /// (On a closed stream it means the input is truncated.)
    Incomplete,
}

/// Error produced by a failed match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchError {
    offset: usize,
    detail: Detail,
    context: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Detail {
    Unexpected {
        expected: Expected,
        found: Option<u8>,
    },
    Incomplete {
        requested: usize,
        available: usize,
    },
    Invalid(Cow<'static, str>),
    TooLarge(Cow<'static, str>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expected {
    Byte(u8),
    // alternatives, as made by `Matcher::or`: stored inline, so that failed alternatives
    // cost no allocation
    OneOf { bytes: [u8; 8], len: u8 },
    Text(Cow<'static, str>),
}

impl Expected {
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Expected::Byte(b) => Some(std::slice::from_ref(b)),
            Expected::OneOf { bytes, len } => Some(&bytes[..*len as usize]),
            Expected::Text(_) => None,
        }
    }

    fn or(&self, other: &Expected) -> Expected {
        if let (Some(a), Some(b)) = (self.bytes(), other.bytes()) {
            let mut bytes = [0u8; 8];
            let mut len = 0;
            for byte in a.iter().chain(b) {
                if !bytes[..len].contains(byte) {
                    if len == bytes.len() {
                        return Expected::Text(format!("{} or {}", self, other).into());
                    }
                    bytes[len] = *byte;
                    len += 1;
                }
            }
            return Expected::OneOf {
                bytes,
                len: len as u8,
            };
        }
        Expected::Text(format!("{} or {}", self, other).into())
    }
}

impl MatchError {
    /// Input at `offset` (the byte `found`, or end of input) is not what was `expected`.
    pub fn unexpected(
        offset: usize,
        found: Option<u8>,
        expected: impl Into<Cow<'static, str>>,
    ) -> MatchError {
        MatchError {
            offset,
            context: None,
            detail: Detail::Unexpected {
                expected: Expected::Text(expected.into()),
                found,
            },
        }
    }

    /// Input at `offset` is the byte `found` (or end of input) instead of byte `expected`.
    pub fn unexpected_byte(offset: usize, found: Option<u8>, expected: u8) -> MatchError {
        MatchError {
            offset,
            context: None,
            detail: Detail::Unexpected {
                expected: Expected::Byte(expected),
                found,
            },
        }
    }

    /// Input at `offset` is well-formed but rejected, e.g. by a limit or a validation.
    pub fn invalid(offset: usize, message: impl Into<Cow<'static, str>>) -> MatchError {
        MatchError {
            offset,
            context: None,
            detail: Detail::Invalid(message.into()),
        }
    }

    /// Input at `offset` exceeds a size limit.
    pub fn too_large(offset: usize, message: impl Into<Cow<'static, str>>) -> MatchError {
        MatchError {
            offset,
            context: None,
            detail: Detail::TooLarge(message.into()),
        }
    }

    /// `requested` bytes are needed at `offset`, but only `available` are buffered.
    pub fn incomplete(offset: usize, requested: usize, available: usize) -> MatchError {
        MatchError {
            offset,
            context: None,
            detail: Detail::Incomplete {
                requested,
                available,
            },
        }
    }

    // Error of a choice where both alternatives failed at the same place: "expected A or B".
    fn or_expected(self, other: MatchError) -> MatchError {
        match (&self.detail, &other.detail) {
            (Detail::Unexpected { expected: a, .. }, Detail::Unexpected { expected: b, found })
                if self.offset == other.offset && self.context.is_none() =>
            {
                MatchError {
                    offset: other.offset,
                    context: other.context,
                    detail: Detail::Unexpected {
                        expected: a.or(b),
                        found: *found,
                    },
                }
            }
            _ => other,
        }
    }

    fn with_context_of(mut self, other: &MatchError) -> MatchError {
        self.context = other.context;
        self
    }

    /// Label the error with `context`, unless it has a context already.
    pub fn with_context(mut self, context: &'static str) -> MatchError {
        self.context.get_or_insert(context);
        self
    }

    /// Innermost context the error occurred in, see [`Matcher::context`].
    pub fn context(&self) -> Option<&'static str> {
        self.context
    }

    /// Category of the error.
    pub fn kind(&self) -> ErrorKind {
        match self.detail {
            Detail::Incomplete { .. } => ErrorKind::Incomplete,
            Detail::TooLarge(_) => ErrorKind::TooLarge,
            _ => ErrorKind::Unexpected,
        }
    }

    /// Position in the stream (see [`ByteStream::offset`]) where the error occurred.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Shorthand for `self.kind() == ErrorKind::Incomplete`.
    pub fn is_incomplete(&self) -> bool {
        self.kind() == ErrorKind::Incomplete
    }
}

struct Byte(u8);

impl fmt::Display for Byte {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.is_ascii_graphic() || self.0 == b' ' {
            write!(f, "'{}'", self.0 as char)
        } else {
            write!(f, "byte 0x{:02X}", self.0)
        }
    }
}

impl fmt::Display for Expected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Expected::Byte(b) => write!(f, "{}", Byte(*b)),
            Expected::OneOf { bytes, len } => {
                for (i, b) in bytes[..*len as usize].iter().enumerate() {
                    if i > 0 {
                        f.write_str(" or ")?;
                    }
                    write!(f, "{}", Byte(*b))?;
                }
                Ok(())
            }
            Expected::Text(t) => f.write_str(t),
        }
    }
}

impl fmt::Display for MatchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "at offset {}: ", self.offset)?;
        if let Some(context) = self.context {
            write!(f, "{}: ", context)?;
        }
        match &self.detail {
            Detail::Unexpected { expected, found } => {
                write!(f, "expected {}", expected)?;
                match found {
                    Some(b) => write!(f, " but found {}", Byte(*b)),
                    None => f.write_str(" but found end of input"),
                }
            }
            Detail::Incomplete {
                requested,
                available,
            } => write!(
                f,
                "requested {} bytes, but only {} available",
                requested, available
            ),
            Detail::Invalid(message) | Detail::TooLarge(message) => f.write_str(message),
        }
    }
}

impl error::Error for MatchError {}
