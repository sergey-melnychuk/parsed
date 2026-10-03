#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod matcher;
pub mod parser;
pub mod stream;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "ws")]
pub mod ws;

#[cfg(test)]
mod testing;

#[cfg(test)]
mod thread_safety {
    use crate::matcher::{Boxed, Resumable};
    use crate::parser::{Matcher, tag, take_until};
    use crate::stream::ByteStream;

    fn send<T: Send>() {}
    fn sync<T: Sync>() {}

    #[test]
    fn parsers_can_move_between_threads() {
        send::<ByteStream<'static>>();
        send::<Boxed<Vec<u8>>>();
        sync::<Boxed<Vec<u8>>>();
        send::<Resumable<Boxed<Vec<u8>>, Vec<u8>>>();
        #[cfg(feature = "http")]
        {
            send::<crate::http::RequestParser>();
            send::<crate::http::ResponseParser>();
            send::<crate::http::BodyDecoder>();
        }
        #[cfg(feature = "ws")]
        {
            send::<crate::ws::FrameParser>();
            send::<crate::ws::MessageReader>();
        }

        // a match started on one thread, finished on another
        let mut parser = Resumable::new(take_until(b"\n").then_ignore(tag(b"\n")).boxed());
        let mut bs = ByteStream::with_capacity(16);
        bs.put(b"hello, ");
        assert!(parser.parse(&mut bs).unwrap_err().is_incomplete());
        let line = std::thread::spawn(move || {
            bs.pull();
            bs.put(b"world\n");
            parser.parse(&mut bs).unwrap()
        })
        .join()
        .unwrap();
        assert_eq!(line, b"hello, world");
    }
}
