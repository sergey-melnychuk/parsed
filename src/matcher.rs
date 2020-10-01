use crate::stream::ByteStream;
use std::{error, fmt};
use std::marker::PhantomData;

pub trait Matcher<T> {
    fn do_match(&self, bs: &mut ByteStream) -> Result<T, MatchError>;

    fn boxed(self) -> Box<dyn Matcher<T>>
    where
        Self: Sized + 'static,
    {
        Box::new(self)
    }

    fn then<U, That>(self, that: That) -> Chain<Self, That>
    where
        Self: Sized,
        That: Matcher<U>,
    {
        Chain(self, that)
    }

    fn then_with<U, F, N>(self, f: F) -> Expose<Self, F>
    where
        Self: Sized,
        F: Fn(&T) -> N + 'static,
        N: Matcher<U>,
    {
        Expose { context: self, next: f }
    }

    fn map<U, F>(self, f: F) -> Map<Self, T, F>
    where
        Self: Sized,
        F: Fn(T) -> U + 'static,
    {
        Map {
            prev: self,
            mapper: f,
            phantom: PhantomData::<T>,
        }
    }

    fn then_map<U, That, F, V>(self, that: That, f: F) -> Map<Chain<Self, That>, (T, U), F>
    where
        Self: Sized,
        That: Matcher<U>,
        F: Fn((T, U)) -> V + 'static,
    {
        self.then(that).map(f)
    }
}

impl<T, F> Matcher<T> for F where F: Fn(&mut ByteStream) -> Result<T, MatchError> {
    fn do_match(&self, bs: &mut ByteStream) -> Result<T, MatchError> {
        (self)(bs)
    }
}

impl<T> Matcher<T> for Box<dyn Matcher<T>> {
    fn do_match(&self, bs: &mut ByteStream) -> Result<T, MatchError> {
        (**self).do_match(bs)
    }
}

// Chain

pub struct Chain<M, N>(M, N);

impl<M, N, T, U> Matcher<(T, U)> for Chain<M, N> where M: Matcher<T>, N: Matcher<U> {
    fn do_match(&self, bs: &mut ByteStream) -> Result<(T, U), MatchError> {
        let t = self.0.do_match(bs)?;
        let u = self.1.do_match(bs)?;
        Ok((t, u))
    }
}

// Expose

pub struct Expose<M, F>{
    context: M,
    next: F,
}

impl<M, F, N, T, U> Matcher<(T, U)> for Expose<M, F>
where
    M: Matcher<T>,
    F: Fn(&T) -> N + 'static,
    N: Matcher<U>,
{
    fn do_match(&self, bs: &mut ByteStream) -> Result<(T, U), MatchError> {
        let t = self.context.do_match(bs)?;
        let g = (self.next)(&t);
        let u = g.do_match(bs)?;
        Ok((t, u))
    }
}

// Map

pub struct Map<M, T, F> {
    prev: M,
    mapper: F,
    phantom: PhantomData<T>,
}

impl<M, T, U, F> Matcher<U> for Map<M, T, F>
where
    M: Matcher<T>,
    F: Fn(T) -> U + 'static,
{
    fn do_match(&self, bs: &mut ByteStream) -> Result<U, MatchError> {
        let t = self.prev.do_match(bs)?;
        let u = (self.mapper)(t);
        Ok(u)
    }
}

pub fn unit<T: 'static, F: Fn() -> T + 'static>(f: F) -> impl Matcher<T> {
    move |_: &mut ByteStream| {
        let t = f();
        Ok(t)
    }
}

#[derive(Debug)]
pub struct MatchError {
    offset: usize,
    message: String,
}

impl MatchError {
    pub fn unexpected(offset: usize, got: String, expected: String) -> MatchError {
        MatchError {
            offset,
            message: format!(
                "MatchError at offset {} expected '{}' but got '{}'",
                offset, expected, got
            ),
        }
    }

    pub fn over_capacity(offset: usize, available: usize, requested: usize) -> MatchError {
        MatchError {
            offset,
            message: format!(
                "MatchError at offset {}, requested {} bytes, but buffer has only {}",
                offset, requested, available
            ),
        }
    }
}

impl fmt::Display for MatchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl error::Error for MatchError {
    fn description(&self) -> &str {
        "MatchError"
    }
    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}
