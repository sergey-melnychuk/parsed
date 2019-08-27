use crate::stream::ByteStream;
use std::error::Error;
use std::fmt::Formatter;
use std::{error, fmt};

pub type Matcher<T> = dyn Fn(&mut ByteStream) -> Result<T, MatchError> + 'static;

pub fn chain<T: 'static, U: 'static>(
    this: Box<Matcher<T>>,
    next: Box<Matcher<U>>,
) -> Box<Matcher<(T, U)>> {
    Box::new(move |bs| {
        let t = (*this)(bs)?;
        let u = (*next)(bs)?;
        Ok((t, u))
    })
}

pub fn expose<T: 'static, U: 'static, F: Fn(&T) -> Box<Matcher<U>> + 'static>(
    this: Box<Matcher<T>>,
    f: F,
) -> Box<Matcher<(T, U)>> {
    Box::new(move |bs| {
        let t = (*this)(bs)?;
        let g = f(&t);
        let u = (*g)(bs)?;
        Ok((t, u))
    })
}

pub fn apply<T: 'static, U: 'static, F: Fn(&mut T, U) + 'static>(
    this: Box<Matcher<(T, U)>>,
    f: F,
) -> Box<Matcher<T>> {
    Box::new(move |bs| {
        let (mut t, u) = (*this)(bs)?;
        f(&mut t, u);
        Ok(t)
    })
}

pub fn map<T: 'static, U: 'static, F: Fn(T) -> U + 'static>(
    this: Box<Matcher<T>>,
    f: F,
) -> Box<Matcher<U>> {
    Box::new(move |bs| {
        let t = (*this)(bs)?;
        let u = f(t);
        Ok(u)
    })
}

pub fn unit<T: 'static, F: Fn() -> T + 'static>(f: F) -> Box<Matcher<T>> {
    Box::new(move |_| {
        let t = f();
        Ok(t)
    })
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

    pub fn not_found(offset: usize, chr: char) -> MatchError {
        MatchError {
            offset,
            message: format!("MatchError at offset {}, '{}' not found", offset, chr),
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
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl error::Error for MatchError {
    fn description(&self) -> &str {
        "MatchError"
    }
    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}
