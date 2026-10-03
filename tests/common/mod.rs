//! Helpers shared by the interoperability tests.
#![allow(dead_code)]

use parsed::matcher::MatchError;
use parsed::stream::ByteStream;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// A blocking connection: a socket plus a buffer that parsers read from. Resumable
/// parsers read with their own `read_from`; [`Conn::read`] drives the others (like the
/// HTTP body decoder).
pub struct Conn {
    pub tcp: TcpStream,
    pub bs: ByteStream<'static>,
}

impl Conn {
    /// Wrap a socket, with a buffer that grows from `initial` up to `max` bytes
    /// (deliberately small in the tests: messages larger than the buffer are parsed
    /// resumably).
    pub fn new(tcp: TcpStream, initial: usize, max: usize) -> Conn {
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        Conn {
            tcp,
            bs: ByteStream::growable(initial, max),
        }
    }

    /// Run `parse` until it completes, reading from the socket whenever it needs more.
    /// `Incomplete` at the end of the input is returned as is.
    pub fn read<T, E>(
        &mut self,
        mut parse: impl FnMut(&mut ByteStream<'static>) -> Result<T, E>,
        incomplete: impl Fn(&E) -> bool,
    ) -> Result<T, E> {
        loop {
            match parse(&mut self.bs) {
                Err(e) if incomplete(&e) && !self.bs.is_closed() => {
                    self.bs.pull();
                    self.bs.read_from(&mut self.tcp).unwrap();
                }
                result => return result,
            }
        }
    }

    /// Shorthand for [`Conn::read`] with parsers that fail with a `MatchError`.
    pub fn parse<T>(
        &mut self,
        parse: impl FnMut(&mut ByteStream<'static>) -> Result<T, MatchError>,
    ) -> Result<T, MatchError> {
        self.read(parse, MatchError::is_incomplete)
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.tcp.write_all(bytes).unwrap();
    }
}

pub fn listen() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// Text with 1- to 4-byte UTF-8 characters.
pub fn text(n: usize) -> String {
    (0..n).map(|i| ['a', 'é', 'ж', '字', '🦀'][i % 5]).collect()
}

pub fn binary(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}
