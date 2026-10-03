//! [`ByteStream`]: the byte buffer that matchers read from.

use std::ops::Range;

/// A saved read position of a [`ByteStream`], see [`ByteStream::mark`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    pos: usize,
}

#[derive(Debug)]
enum Buf<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a [u8]),
}

/// A byte buffer with a read position: either an owned fixed-capacity buffer, or a
/// borrowed slice that is read without copying.
///
/// Bytes are appended to an owned buffer with [`put`](ByteStream::put) and consumed by
/// matchers. [`pull`](ByteStream::pull) drops consumed bytes to make room for new ones.
///
/// Positions come in two flavours: [`pos`](ByteStream::pos) is relative to the current
/// buffer (and changes on `pull`), while [`offset`](ByteStream::offset) counts from the
/// start of the whole stream (errors and spans use offsets, see
/// [`slice`](ByteStream::slice)).
///
/// A stream is either *open* (more bytes may arrive: [`with_capacity`](ByteStream::with_capacity),
/// [`partial`](ByteStream::partial)) or *closed* (the buffered bytes are all the input
/// there is: [`wrap`](ByteStream::wrap), [`borrow`](ByteStream::borrow), `From`, or after
/// [`close`](ByteStream::close)). The difference matters to matchers that take a variable
/// number of items, like [`repeat`](crate::parser::repeat) or
/// [`take_while`](crate::parser::take_while): at the end of an open stream they can't
/// tell if they are done, so they report [`Incomplete`](crate::matcher::ErrorKind::Incomplete).
#[derive(Debug)]
pub struct ByteStream<'a> {
    buf: Buf<'a>,
    pos: usize,
    // number of bytes dropped by `pull`
    base: usize,
    closed: bool,
    // maximum size of an owned buffer
    max: usize,
    // end of the readable window (buffer index), set by `restrict` and `restrict_frame`
    end: Option<usize>,
    // whether the end of the window is the end of the input (a frame fully buffered)
    end_closed: bool,
}

/// Saved window of a [`ByteStream`], see [`ByteStream::restrict`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Window {
    end: Option<usize>,
    end_closed: bool,
}

impl ByteStream<'static> {
    /// Closed stream over complete input.
    pub fn wrap(buf: Vec<u8>) -> Self {
        ByteStream {
            max: buf.len(),
            buf: Buf::Owned(buf),
            pos: 0,
            base: 0,
            closed: true,
            end: None,
            end_closed: false,
        }
    }

    /// Empty open stream that can buffer up to `cap` bytes (allocated up-front).
    pub fn with_capacity(cap: usize) -> Self {
        ByteStream {
            max: cap,
            ..ByteStream::growable(cap, cap)
        }
    }

    /// Empty open stream starting with `initial` bytes of capacity, that grows as needed
    /// up to `max` bytes.
    pub fn growable(initial: usize, max: usize) -> Self {
        ByteStream {
            buf: Buf::Owned(Vec::with_capacity(initial.min(max))),
            pos: 0,
            base: 0,
            closed: false,
            max,
            end: None,
            end_closed: false,
        }
    }
}

impl<'a> ByteStream<'a> {
    /// Closed stream reading complete input from `slice`, without copying it.
    pub fn borrow(slice: &'a [u8]) -> Self {
        ByteStream {
            buf: Buf::Borrowed(slice),
            pos: 0,
            base: 0,
            closed: true,
            max: 0,
            end: None,
            end_closed: false,
        }
    }

    /// Open stream reading from `slice` without copying it: `slice` is what has been
    /// received so far, and more may follow (so parsing can end with `Incomplete`).
    pub fn partial(slice: &'a [u8]) -> Self {
        ByteStream {
            closed: false,
            ..ByteStream::borrow(slice)
        }
    }

    fn all(&self) -> &[u8] {
        match &self.buf {
            Buf::Owned(v) => v,
            Buf::Borrowed(s) => s,
        }
    }

    fn data(&self) -> &[u8] {
        let all = self.all();
        match self.end {
            Some(end) => &all[..end],
            None => all,
        }
    }

    /// Hide all but the next `n` readable bytes until [`unrestrict`](Self::unrestrict).
    /// While bytes are hidden the stream looks open. Returns the window to restore.
    pub(crate) fn restrict(&mut self, n: usize) -> Window {
        let saved = self.window();
        let end = self.pos.saturating_add(n);
        if end < self.len() {
            self.end = Some(end);
            self.end_closed = false;
        }
        saved
    }

    /// Hide everything beyond the next `n` bytes, which are a frame of their own: if the
    /// whole frame is buffered, the stream looks closed at its end. Returns the window
    /// to restore.
    pub(crate) fn restrict_frame(&mut self, n: usize) -> Window {
        let saved = self.window();
        let end = self.pos.saturating_add(n);
        if end <= self.len() {
            self.end = Some(end);
            self.end_closed = true;
        }
        saved
    }

    /// Whether the whole frame set by [`restrict_frame`](Self::restrict_frame) is visible.
    pub(crate) fn is_frame_buffered(&self) -> bool {
        self.end.is_some() && self.end_closed
    }

    fn window(&self) -> Window {
        Window {
            end: self.end,
            end_closed: self.end_closed,
        }
    }

    /// Whether [`restrict`](Self::restrict) currently hides bytes.
    pub(crate) fn is_restricted(&self) -> bool {
        self.end.is_some_and(|end| end < self.all().len())
    }

    pub(crate) fn unrestrict(&mut self, window: Window) {
        self.end = window.end;
        self.end_closed = window.end_closed;
    }

    /// Mark the stream as closed: no more bytes will be put into it.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Whether the stream is closed, see [`ByteStream::close`].
    pub fn is_closed(&self) -> bool {
        match self.end {
            Some(_) => self.end_closed,
            None => self.closed,
        }
    }

    /// Current read position in the buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Current read position counted from the start of the stream: unlike
    /// [`pos`](ByteStream::pos), it does not change on [`pull`](ByteStream::pull).
    pub fn offset(&self) -> usize {
        self.base + self.pos
    }

    /// Number of buffered bytes, including the consumed ones.
    pub fn len(&self) -> usize {
        self.data().len()
    }

    /// Whether nothing is buffered.
    pub fn is_empty(&self) -> bool {
        self.data().is_empty()
    }

    /// Number of bytes available for reading (after the current read position).
    pub fn remaining(&self) -> usize {
        self.len() - self.pos
    }

    /// Number of bytes that can still be put into the buffer (always 0 for a borrowed
    /// stream).
    pub fn cap(&self) -> usize {
        match &self.buf {
            Buf::Owned(v) => self.max.saturating_sub(v.len()),
            Buf::Borrowed(_) => 0,
        }
    }

    /// Whether the stream is stuck: an owned buffer that is full, with nothing consumed
    /// that [`pull`](ByteStream::pull) could drop. A match that is still `Incomplete`
    /// then can never complete (see [`Matcher::do_match`](crate::matcher::Matcher::do_match)).
    pub fn is_full(&self) -> bool {
        matches!(self.buf, Buf::Owned(_)) && self.cap() == 0 && self.pos == 0 && !self.closed
    }

    /// Append all of `buf` if it fits, returning the number of bytes appended
    /// (`buf.len()` or 0). See [`put_some`](ByteStream::put_some) to append what fits.
    pub fn put(&mut self, buf: &[u8]) -> usize {
        if buf.len() <= self.cap() {
            self.put_some(buf)
        } else {
            0
        }
    }

    /// Append as much of `buf` as fits, returning the number of bytes appended.
    pub fn put_some(&mut self, buf: &[u8]) -> usize {
        let n = buf.len().min(self.cap());
        match &mut self.buf {
            Buf::Owned(v) => v.extend_from_slice(&buf[..n]),
            Buf::Borrowed(_) => return 0,
        }
        n
    }

    /// Read from `reader` directly into the buffer (at most [`cap`](ByteStream::cap)
    /// bytes, and at most 64 KiB at a time), returning the number of bytes read. At the
    /// end of the input (a read of 0 bytes) the stream is closed.
    ///
    /// Fails with [`std::io::ErrorKind::OutOfMemory`] if there is no room in the buffer:
    /// call [`pull`](ByteStream::pull) first.
    pub fn read_from<R: std::io::Read>(&mut self, reader: &mut R) -> std::io::Result<usize> {
        let room = self.cap().min(64 << 10);
        let Buf::Owned(v) = &mut self.buf else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "borrowed stream",
            ));
        };
        if room == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "stream buffer is full",
            ));
        }
        let len = v.len();
        v.resize(len + room, 0);
        let result = loop {
            match reader.read(&mut v[len..]) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                result => break result,
            }
        };
        v.truncate(len + *result.as_ref().unwrap_or(&0));
        if let Ok(0) = result {
            self.closed = true;
        }
        result
    }

    /// Append a byte, returning whether it fit.
    pub fn put_u8(&mut self, b: u8) -> bool {
        self.put(&[b]) == 1
    }

    /// Append a big-endian `u16`, returning whether it fit.
    pub fn put_u16(&mut self, b: u16) -> bool {
        self.put(&b.to_be_bytes()) == 2
    }

    /// Append a big-endian `u32`, returning whether it fit.
    pub fn put_u32(&mut self, b: u32) -> bool {
        self.put(&b.to_be_bytes()) == 4
    }

    /// Append a big-endian `u64`, returning whether it fit.
    pub fn put_u64(&mut self, b: u64) -> bool {
        self.put(&b.to_be_bytes()) == 8
    }

    /// Append 16 bytes, returning whether they fit.
    pub fn put_16(&mut self, b: [u8; 16]) -> bool {
        self.put(&b) == 16
    }

    /// Append 32 bytes, returning whether they fit.
    pub fn put_32(&mut self, b: [u8; 32]) -> bool {
        self.put(&b) == 32
    }

    /// Borrow the next `n` bytes and advance, if that many are available.
    pub fn take(&mut self, n: usize) -> Option<&[u8]> {
        if n <= self.remaining() {
            let offset = self.pos;
            self.pos += n;
            Some(&self.data()[offset..offset + n])
        } else {
            None
        }
    }

    /// Advance by `n` bytes (at most up to the end of the buffer), returning the number
    /// of bytes skipped.
    pub fn skip(&mut self, n: usize) -> usize {
        let n = n.min(self.remaining());
        self.pos += n;
        n
    }

    /// Copy the next `n` bytes and advance, if that many are available.
    pub fn get(&mut self, n: usize) -> Option<Vec<u8>> {
        self.take(n).map(|s| s.to_vec())
    }

    /// Read the next `N` bytes as an array.
    pub fn get_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).map(|s| {
            let mut r = [0u8; N];
            r.copy_from_slice(s);
            r
        })
    }

    /// Read a byte.
    pub fn get_u8(&mut self) -> Option<u8> {
        self.next()
    }

    /// Read a big-endian `u16`.
    pub fn get_u16(&mut self) -> Option<u16> {
        self.get_array().map(u16::from_be_bytes)
    }

    /// Read a big-endian `u32`.
    pub fn get_u32(&mut self) -> Option<u32> {
        self.get_array().map(u32::from_be_bytes)
    }

    /// Read a big-endian `u64`.
    pub fn get_u64(&mut self) -> Option<u64> {
        self.get_array().map(u64::from_be_bytes)
    }

    /// Read 16 bytes.
    pub fn get_16(&mut self) -> Option<[u8; 16]> {
        self.get_array()
    }

    /// Read 32 bytes.
    pub fn get_32(&mut self) -> Option<[u8; 32]> {
        self.get_array()
    }

    /// The next byte, without advancing.
    pub fn peek(&self) -> Option<u8> {
        self.data().get(self.pos).copied()
    }

    /// Read the next byte.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    /// Save the current read position.
    pub fn mark(&self) -> Mark {
        Mark { pos: self.pos }
    }

    /// Move the read position back to `mark` (ignored if `mark` is ahead of it).
    pub fn reset(&mut self, mark: Mark) {
        if mark.pos <= self.pos {
            self.pos = mark.pos;
        }
    }

    /// Drop all buffered bytes.
    pub fn clear(&mut self) {
        self.base += self.len();
        self.pos = 0;
        match &mut self.buf {
            Buf::Owned(v) => v.clear(),
            Buf::Borrowed(s) => *s = &[],
        }
    }

    /// Drop the bytes before the current read position, making room for more bytes to be
    /// put into the buffer. Invalidates all previously taken marks and slices.
    pub fn pull(&mut self) {
        if self.pos > 0 {
            match &mut self.buf {
                Buf::Owned(v) => {
                    v.drain(..self.pos);
                }
                Buf::Borrowed(s) => *s = &s[self.pos..],
            }
            self.base += self.pos;
            self.pos = 0;
        }
    }

    /// Bytes of the given range of stream offsets (as produced by
    /// [`recognize`](crate::parser::recognize)), if they are still buffered.
    pub fn slice(&self, range: Range<usize>) -> Option<&[u8]> {
        let start = range.start.checked_sub(self.base)?;
        let end = range.end.checked_sub(self.base)?;
        self.data().get(start..end)
    }

    /// Index (in the buffer) of the first unread byte matching the predicate.
    pub fn find_single<F: Fn(&u8) -> bool>(&self, f: F) -> Option<usize> {
        self.data()[self.pos..]
            .iter()
            .position(f)
            .map(|idx| idx + self.pos)
    }

    /// Index (in the buffer) of the first unread window of `w` bytes matching the predicate.
    pub fn find_window<F: Fn(&[u8]) -> bool>(&self, w: usize, f: F) -> Option<usize> {
        self.data()[self.pos..]
            .windows(w)
            .position(f)
            .map(|idx| idx + self.pos)
    }
}

impl AsRef<[u8]> for ByteStream<'_> {
    /// The unread bytes.
    fn as_ref(&self) -> &[u8] {
        &self.data()[self.pos..]
    }
}

impl<'a> From<&'a [u8]> for ByteStream<'a> {
    fn from(s: &'a [u8]) -> Self {
        ByteStream::borrow(s)
    }
}

impl From<String> for ByteStream<'static> {
    fn from(s: String) -> Self {
        ByteStream::wrap(s.into_bytes())
    }
}

impl From<Vec<u8>> for ByteStream<'static> {
    fn from(v: Vec<u8>) -> Self {
        ByteStream::wrap(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::QuickCheck;

    fn stream(cap: usize) -> ByteStream<'static> {
        ByteStream::with_capacity(cap)
    }

    #[test]
    fn test_u64() {
        fn f(x: u64) -> bool {
            let mut bs = stream(8);
            bs.put_u64(x) && bs.get_u64() == Some(x) && bs.remaining() == 0
        }
        QuickCheck::new().quickcheck(f as fn(u64) -> bool);
    }

    #[test]
    fn test_u32() {
        fn f(x: u32) -> bool {
            let mut bs = stream(4);
            bs.put_u32(x) && bs.get_u32() == Some(x) && bs.remaining() == 0
        }
        QuickCheck::new().quickcheck(f as fn(u32) -> bool);
    }

    #[test]
    fn test_u16() {
        fn f(x: u16) -> bool {
            let mut bs = stream(2);
            bs.put_u16(x) && bs.get_u16() == Some(x) && bs.remaining() == 0
        }
        QuickCheck::new().quickcheck(f as fn(u16) -> bool);
    }

    #[test]
    fn big_endian() {
        let mut bs = stream(14);
        assert!(bs.put_u16(0x0102));
        assert!(bs.put_u32(0x03040506));
        assert!(bs.put_u64(0x0708090A0B0C0D0E));
        assert_eq!(bs.as_ref(), &(1u8..=14).collect::<Vec<u8>>()[..]);
    }

    #[test]
    fn put_over_capacity() {
        let mut bs = stream(3);
        assert!(!bs.put_u32(1));
        assert!(bs.put_u16(1));
        assert!(!bs.put_u16(1));
        assert!(bs.put_u8(1));
        assert!(!bs.put_u8(1));
        assert_eq!(bs.len(), 3);
    }

    #[test]
    fn get_arrays() {
        let data: Vec<u8> = (0u8..48).collect();
        let mut bs = ByteStream::wrap(data.clone());
        assert_eq!(&bs.get_16().unwrap()[..], &data[0..16]);
        assert_eq!(&bs.get_32().unwrap()[..], &data[16..48]);
        assert_eq!(bs.get_16(), None);
        assert_eq!(bs.pos(), 48);
    }

    #[test]
    fn get_insufficient_does_not_advance() {
        let mut bs = ByteStream::wrap(vec![1, 2, 3]);
        assert_eq!(bs.get_u32(), None);
        assert_eq!(bs.pos(), 0);
        assert_eq!(bs.get(3), Some(vec![1, 2, 3]));
        assert_eq!(bs.next(), None);
        assert_eq!(bs.peek(), None);
    }

    #[test]
    fn pull_keeps_capacity_and_unread_bytes() {
        let mut bs = stream(4);
        assert_eq!(bs.put(&[1, 2, 3, 4]), 4);
        assert_eq!(bs.cap(), 0);
        assert_eq!(bs.get(3), Some(vec![1, 2, 3]));
        bs.pull();
        assert_eq!(bs.pos(), 0);
        assert_eq!(bs.as_ref(), &[4]);
        assert_eq!(bs.cap(), 3);
        assert_eq!(bs.put(&[5, 6, 7]), 3);
        assert_eq!(bs.as_ref(), &[4, 5, 6, 7]);
    }

    #[test]
    fn mark_reset() {
        let mut bs = ByteStream::wrap(vec![1, 2, 3]);
        let m = bs.mark();
        bs.next();
        bs.next();
        bs.reset(m);
        assert_eq!(bs.pos(), 0);
    }

    #[test]
    fn borrowed_stream_reads_without_copying() {
        let data = [1u8, 2, 3, 4, 5];
        let mut bs = ByteStream::borrow(&data);
        assert!(bs.is_closed());
        assert_eq!(bs.cap(), 0);
        assert_eq!(bs.put(&[6]), 0);
        assert_eq!(bs.take(2).unwrap().as_ptr(), data.as_ptr());
        bs.pull();
        assert_eq!(bs.pos(), 0);
        assert_eq!(bs.offset(), 2);
        assert_eq!(bs.as_ref(), &[3, 4, 5]);
        assert!(!ByteStream::partial(&data).is_closed());
    }

    #[test]
    fn offsets_and_slices_survive_pull() {
        let mut bs = stream(4);
        bs.put(&[1, 2, 3, 4]);
        bs.skip(3);
        assert_eq!(bs.slice(1..3), Some(&[2u8, 3][..]));
        bs.pull();
        assert_eq!(bs.offset(), 3);
        assert_eq!(bs.slice(1..3), None, "dropped by pull");
        assert_eq!(bs.slice(3..4), Some(&[4u8][..]));
        bs.put(&[5, 6]);
        assert_eq!(bs.slice(3..6), Some(&[4u8, 5, 6][..]));
        assert_eq!(bs.slice(3..7), None);
        bs.clear();
        assert_eq!(bs.offset(), 6);
    }
}
