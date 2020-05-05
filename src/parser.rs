use crate::stream::{ByteStream, ToStream};
use crate::matcher::{MatchError, expose};
use crate::matcher::{apply, unit, chain, map, Matcher};

pub struct Parser<T> {
    f: Box<Matcher<T>>,
}

impl<T> Into<Box<Matcher<T>>> for Parser<T> {
    fn into(self) -> Box<Matcher<T>> {
        self.f
    }
}

impl<T: 'static> Parser<T> {
    pub fn unit(f: Box<Matcher<T>>) -> Parser<T> {
        Parser { f }
    }

    pub fn init<F: Fn() -> T + 'static>(f: F) -> Parser<T> {
        Parser::unit(unit(f))
    }

    pub fn then<U: 'static>(self, that: Box<Matcher<U>>) -> Parser<(T, U)> {
        Parser::unit(chain(self.f, that))
    }

    pub fn map<U: 'static, F: Fn(T) -> U + 'static>(self, f: F) -> Parser<U> {
        Parser::unit(map(self.f, f))
    }

    pub fn then_map<U: 'static, V: 'static, F: Fn((T, U)) -> V + 'static>(
        self,
        that: Box<Matcher<U>>,
        f: F,
    ) -> Parser<V> {
        Parser::unit(map(chain(self.f, that), f))
    }

    // This is something similar to flat_map
    pub fn then_with<U: 'static, F: Fn(&T) -> Box<Matcher<U>> + 'static>(self, f: F) -> Parser<(T, U)> {
        Parser::unit(expose(self.f, f))
    }
}

impl<T: 'static, U: 'static> Parser<(T, U)> {
    pub fn save<F: Fn(&mut T, U) + 'static>(self, f: F) -> Parser<T> {
        Parser::unit(apply(self.f, f))
    }

    pub fn skip(self) -> Parser<T> {
        self.map(|(t, _)| t)
    }
}

pub fn one(b: u8) -> Box<Matcher<u8>> {
    Box::new(move |bs| {
        let pos = bs.pos();
        bs.next().filter(|x| *x == b).ok_or(MatchError::unexpected(
            pos,
            format!("EOF"),
            format!("byte {}", b),
        ))
    })
}

pub fn single(chr: char) -> Box<Matcher<char>> {
    Box::new(move |bs| {
        let pos = bs.pos();
        bs.next()
            .map(|b| b as char)
            .filter(|c| *c == chr)
            .ok_or(MatchError::unexpected(
                pos,
                format!("EOF"),
                format!("{}", chr),
            ))
    })
}

pub fn repeat<T: 'static>(this: Box<Matcher<T>>) -> Box<Matcher<Vec<T>>> {
    Box::new(move |bs| {
        let mut acc: Vec<T> = vec![];
        loop {
            let mark = bs.mark();
            match (*this)(bs) {
                Err(_) => {
                    bs.reset(mark);
                    return Ok(acc);
                }
                Ok(t) => acc.push(t),
            }
        }
    })
}

pub fn maybe<T: 'static>(this: Box<Matcher<T>>) -> Box<Matcher<Option<T>>> {
    Box::new(move |bs| {
        let mark = bs.mark();
        match (*this)(bs) {
            Ok(m) => Ok(Some(m)),
            Err(_) => {
                bs.reset(mark);
                Ok(None)
            }
        }
    })
}

pub fn until<F: Fn(u8) -> bool + 'static>(f: F) -> Box<Matcher<Vec<u8>>> {
    Box::new(move |bs| {
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
    })
}

pub fn before(chr: char) -> Box<Matcher<Vec<u8>>> {
    Box::new(move |bs| {
        let pos = bs.pos();
        bs.find_single(|c| *c == chr as u8)
            .map(|idx| idx - pos)
            .and_then(|len| bs.get(len))
            .ok_or(MatchError::not_found(pos, chr))
    })
}

pub fn token() -> Box<Matcher<String>> {
    Box::new(move |bs| {
        let u = before(' ');
        (*u)(bs).map(|vec| vec.into_iter().map(|b| b as char).collect::<String>())
    })
}

pub fn exact(slice: &'static [u8]) -> Box<Matcher<Vec<u8>>> {
    Box::new(move |bs| {
        let mark = bs.mark();
        let mut acc = vec![];
        for i in 0..slice.len() {
            let b = slice[i];
            let s = single(b as char);
            match (*s)(bs) {
                Ok(b) => acc.push(b),
                Err(e) => {
                    bs.reset(mark);
                    return Err(e);
                }
            }
        }

        Ok(acc.into_iter().map(|c| c as u8).collect())
    })
}

pub fn string(s: &'static str) -> Box<Matcher<String>> {
    Box::new(move |bs| {
        let m = exact(s.as_bytes());
        let mark = bs.mark();
        match (*m)(bs) {
            Ok(vec) => Ok(String::from_utf8(vec).unwrap()),
            Err(e) => {
                bs.reset(mark);
                return Err(e);
            }
        }
    })
}

pub fn space() -> Box<Matcher<Vec<char>>> {
    Box::new(move |bs| {
        let f: fn(u8) -> bool = |b| (b as char).is_whitespace();
        match (*until(f))(bs) {
            Ok(vec) => Ok(vec.into_iter().map(|b| b as char).collect()),
            Err(e) => Err(e),
        }
    })
}

pub fn bytes(len: usize) -> Box<Matcher<Vec<u8>>> {
    Box::new(move |bs| {
        bs.get(len)
            .ok_or(MatchError::over_capacity(bs.pos(), bs.len(), len))
    })
}

pub trait Applicator {
    fn apply<T>(&mut self, parser: Parser<T>) -> Result<T, MatchError>;
}

impl Applicator for ByteStream {
    fn apply<T>(&mut self, parser: Parser<T>) -> Result<T, MatchError> {
        (*(parser.f))(self)
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

        let m = Parser::init(|| TokenBuilder::zero())
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

        let abccc = Parser::init(|| vec![])
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

        let until1 = Parser::init(|| ())
            .then_map(before('1'), |(_, vec)| {
                vec.into_iter().map(|b| b as char).collect::<String>()
            })
            .then_map(single('1'), |(vec, one)| (vec, one));

        assert_eq!(bs.apply(until1).unwrap(), ("asdasdasdasd".to_string(), '1'));
    }

    #[test]
    fn chunks() {
        let mut bs = "asdasdqqq123123token1 token2\n".to_string().into_stream();

        let m = Parser::init(|| vec![])
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