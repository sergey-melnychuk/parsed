use crate::stream::{ByteStream, ToStream};
pub use crate::matcher::{MatcherTrait, MatchError, unit, Matcher};
use std::marker::PhantomData;

pub struct Save<M, T, U, F> {
    matcher: M,
    func: F,
    phantom: PhantomData<(T, U)>,
}

impl<M, T, U, F> MatcherTrait<T> for Save<M, T, U, F>
where
    M: MatcherTrait<(T, U)>,
    F: Fn(&mut T, U),
{
    fn do_match(&self, bs: &mut ByteStream) -> Result<T, MatchError> {
        let (mut t, u) = self.matcher.do_match(bs)?;
        (self.func)(&mut t, u);
        Ok(t)
    }
}

pub struct Skip<M, T, U> {
    matcher: M,
    phantom: PhantomData<(T, U)>,
}

impl<M, T, U> MatcherTrait<T> for Skip<M, T, U>
where
    M: MatcherTrait<(T, U)>,
{
    fn do_match(&self, bs: &mut ByteStream) -> Result<T, MatchError> {
        let (t, _u) = self.matcher.do_match(bs)?;
        Ok(t)
    }
}

pub trait ParserExt<T, U>: Sized {
    fn save<F: Fn(&mut T, U) + 'static>(self, f: F) -> Save<Self, T, U, F>;

    fn skip(self) -> Skip<Self, T, U>;
}

impl<M, T, U> ParserExt<T, U> for M where M: MatcherTrait<(T, U)> + Sized {
    fn save<F: Fn(&mut T, U) + 'static>(self, f: F) -> Save<Self, T, U, F> {
        Save {
            matcher: self,
            func: f,
            phantom: PhantomData::<(T, U)>,
        }
    }

    fn skip(self) -> Skip<Self, T, U> {
        Skip {
            matcher: self,
            phantom: PhantomData::<(T, U)>,
        }
    }
}

pub fn one(b: u8) -> impl MatcherTrait<u8> {
    move |bs: &mut ByteStream| {
        let pos = bs.pos();
        bs.next().filter(|x| *x == b).ok_or(MatchError::unexpected(
            pos,
            format!("EOF"),
            format!("byte {}", b),
        ))
    }
}

pub fn single(chr: char) -> impl MatcherTrait<char> {
    move |bs: &mut ByteStream| {
        let pos = bs.pos();
        bs.next()
            .map(|b| b as char)
            .filter(|c| *c == chr)
            .ok_or(MatchError::unexpected(
                pos,
                format!("EOF"),
                format!("{}", chr),
            ))
    }
}

pub fn repeat<T: 'static>(this: impl MatcherTrait<T>) -> impl MatcherTrait<Vec<T>> {
    move |bs: &mut ByteStream| {
        let mut acc: Vec<T> = vec![];
        loop {
            let mark = bs.mark();
            match this.do_match(bs) {
                Err(_) => {
                    bs.reset(mark);
                    return Ok(acc);
                }
                Ok(t) => acc.push(t),
            }
        }
    }
}

pub fn maybe<T: 'static>(this: impl  MatcherTrait<T>) -> impl MatcherTrait<Option<T>> {
    move |bs: &mut ByteStream| {
        let mark = bs.mark();
        match this.do_match(bs) {
            Ok(m) => Ok(Some(m)),
            Err(_) => {
                bs.reset(mark);
                Ok(None)
            }
        }
    }
}

pub fn until<F: Fn(u8) -> bool + 'static>(f: F) -> impl MatcherTrait<Vec<u8>> {
    move |bs: &mut ByteStream| {
        let mut acc = vec![];
        loop {
            let mark = bs.mark();
            match bs.next() {
                Some(b) if f(b) => acc.push(b),
                _ => {
                    bs.reset(mark);
                    return Ok(acc);
                }
            }
        }
    }
}

pub fn before(chr: char) -> impl MatcherTrait<Vec<u8>> {
    move |bs: &mut ByteStream| {
        let pos = bs.pos();
        bs.find_single(|c| *c == chr as u8)
            .map(|idx| idx - pos)
            .and_then(|len| bs.get(len))
            .ok_or(MatchError::not_found(pos, chr))
    }
}

pub fn token() -> impl MatcherTrait<String> {
    before(' ').map(|vec| vec.into_iter().map(|b| b as char).collect::<String>())
}

pub fn exact(slice: &'static [u8]) -> impl MatcherTrait<Vec<u8>> {
    move |bs: &mut ByteStream| {
        let mark = bs.mark();
        let mut acc = vec![];
        for i in 0..slice.len() {
            let b = slice[i];
            let s = single(b as char);
            match s.do_match(bs) {
                Ok(b) => acc.push(b),
                Err(e) => {
                    bs.reset(mark);
                    return Err(e);
                }
            }
        }

        Ok(acc.into_iter().map(|c| c as u8).collect())
    }
}

pub fn string(s: &'static str) -> impl MatcherTrait<String> {
    move |bs: &mut ByteStream| {
        let m = exact(s.as_bytes());
        let mark = bs.mark();
        match m.do_match(bs) {
            Ok(vec) => Ok(String::from_utf8(vec).unwrap()),
            Err(e) => {
                bs.reset(mark);
                return Err(e);
            }
        }
    }
}

pub fn space() -> impl MatcherTrait<Vec<char>> {
    move |bs: &mut ByteStream| {
        let f: fn(u8) -> bool = |b| (b as char).is_whitespace();
        match until(f).do_match(bs) {
            Ok(vec) => Ok(vec.into_iter().map(|b| b as char).collect()),
            Err(e) => Err(e),
        }
    }
}

pub fn bytes(len: usize) -> impl MatcherTrait<Vec<u8>> {
    move |bs: &mut ByteStream| {
        bs.get(len)
            .ok_or(MatchError::over_capacity(bs.pos(), bs.len(), len))
    }
}

pub trait Applicator {
    fn apply<T>(&mut self, parser: impl MatcherTrait<T>) -> Result<T, MatchError>;
}

impl Applicator for ByteStream {
    fn apply<T>(&mut self, parser: impl MatcherTrait<T>) -> Result<T, MatchError> {
        parser.do_match(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let mut bs = "abc".to_string().into_stream();

        let m = unit(|| TokenBuilder::zero())
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
        let mut bs = "abccc".to_string().into_stream();

        let c = single('c');

        let abccc = unit(|| vec![])
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
        let mut bs = "asdasdasdasd1".to_string().into_stream();

        let until1 = unit(|| ())
            .then_map(before('1'), |(_, vec)| {
                vec.into_iter().map(|b| b as char).collect::<String>()
            })
            .then_map(single('1'), |(vec, one)| (vec, one));

        assert_eq!(bs.apply(until1).unwrap(), ("asdasdasdasd".to_string(), '1'));
    }

    #[test]
    fn chunks() {
        let mut bs = "asdasdqqq123123token1 token2\n".to_string().into_stream();

        let m = unit(|| vec![])
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
}