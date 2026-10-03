//! RESP2, the Redis protocol
//! (<https://redis.io/docs/latest/develop/reference/protocol-spec/>): values, their parser
//! and their encoding.

use parsed::matcher::Boxed;
use parsed::parser::{
    Either, Matcher, bytes, fail, integer, lazy, limit, preceded, tag, take_until, times, unit,
};

/// A RESP value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Simple(String),
    Error(String),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
    Array(Option<Vec<Value>>),
}

// Limits keep a hostile peer from exhausting memory or the stack.
const MAX_LINE: usize = 64 << 10;
const MAX_BULK: usize = 512 << 20;
const MAX_ARRAY: usize = 1 << 20;
const MAX_DEPTH: usize = 32;

fn crlf() -> impl Matcher<()> {
    tag(b"\r\n")
}

fn line() -> impl Matcher<String> {
    limit(MAX_LINE, take_until(b"\r\n"))
        .then_ignore(crlf())
        .try_map(|v| String::from_utf8(v).map_err(|_| "invalid UTF-8"))
}

// "-1" means null
fn length(max: usize) -> impl Matcher<Option<usize>> {
    integer().then_ignore(crlf()).try_map(move |n| match n {
        -1 => Ok(None),
        n if n < 0 => Err("negative length"),
        n if n as u64 > max as u64 => Err("length too large"),
        n => Ok(Some(n as usize)),
    })
}

/// Matcher for a RESP value; `depth` is the current nesting depth (start with 0).
pub fn value(depth: usize) -> Boxed<Value> {
    if depth > MAX_DEPTH {
        return fail("nested too deeply").boxed();
    }
    let simple = preceded(tag(b"+"), line()).map(Value::Simple);
    let error = preceded(tag(b"-"), line()).map(Value::Error);
    let int = preceded(tag(b":"), integer().then_ignore(crlf())).map(Value::Integer);
    let bulk = preceded(tag(b"$"), length(MAX_BULK))
        .then_with(|len| match *len {
            None => Either::Left(unit(|| None)),
            // accumulated as it arrives: may be larger than the buffer
            Some(n) => Either::Right(bytes(n).then_ignore(crlf()).map(Some)),
        })
        .map(|(_, data)| Value::Bulk(data));
    let array = preceded(tag(b"*"), length(MAX_ARRAY))
        .then_with(move |len| match *len {
            None => Either::Left(unit(|| None)),
            Some(n) => Either::Right(times(n, lazy(move || value(depth + 1))).map(Some)),
        })
        .map(|(_, items)| Value::Array(items));
    simple
        .or(error)
        .or(int)
        .or(bulk)
        .or(array)
        .context("RESP value")
        .boxed()
}

/// Append the RESP encoding of `value`.
pub fn encode(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Simple(s) => out.extend_from_slice(format!("+{}\r\n", s).as_bytes()),
        Value::Error(s) => out.extend_from_slice(format!("-{}\r\n", s).as_bytes()),
        Value::Integer(n) => out.extend_from_slice(format!(":{}\r\n", n).as_bytes()),
        Value::Bulk(None) => out.extend_from_slice(b"$-1\r\n"),
        Value::Bulk(Some(data)) => {
            out.extend_from_slice(format!("${}\r\n", data.len()).as_bytes());
            out.extend_from_slice(data);
            out.extend_from_slice(b"\r\n");
        }
        Value::Array(None) => out.extend_from_slice(b"*-1\r\n"),
        Value::Array(Some(items)) => {
            out.extend_from_slice(format!("*{}\r\n", items.len()).as_bytes());
            for item in items {
                encode(item, out);
            }
        }
    }
}
