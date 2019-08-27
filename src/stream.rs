pub struct Mark {
    pos: usize,
}

pub struct ByteStream {
    buf: Vec<u8>,
    pos: usize,
}

impl ByteStream {
    pub fn wrap(buf: Vec<u8>) -> ByteStream {
        ByteStream { buf, pos: 0 }
    }

    pub fn with_capacity(cap: usize) -> ByteStream {
        ByteStream {
            buf: Vec::with_capacity(cap),
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn cap(&self) -> usize {
        self.buf.capacity() - self.buf.len()
    }

    pub fn put(&mut self, buf: &[u8]) -> usize {
        if self.cap() >= buf.len() {
            for b in buf {
                self.buf.push(*b);
            }
            buf.len()
        } else {
            0
        }
    }

    pub fn get(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.pos + n <= self.buf.len() {
            let mut result = Vec::with_capacity(n);
            let offset = self.pos;
            for i in offset..(offset + n) {
                result.push(self.buf[i]);
                self.pos += 1;
            }
            Some(result)
        } else {
            None
        }
    }

    pub fn next(&mut self) -> Option<u8> {
        self.get(1).map(|ref v| v[0])
    }

    pub fn mark(&self) -> Mark {
        Mark { pos: self.pos }
    }

    pub fn reset(&mut self, mark: Mark) {
        if mark.pos <= self.pos {
            self.pos = mark.pos;
        }
    }

    // drop bytes before current read position, allows more bytes to be put into the buffer
    pub fn pull(&mut self) {
        if self.pos > 0 && self.len() > 0 {
            let len = self.pos;
            let mut buf = Vec::with_capacity(self.buf.capacity());
            buf.append(&mut self.buf[len..].to_vec());
            self.buf = buf;
            self.pos = 0;
        }
    }

    // find index of a first byte that matches predicate
    pub fn find_single<F: Fn(&u8) -> bool>(&self, f: F) -> Option<usize> {
        self.buf[self.pos..]
            .iter()
            .position(f)
            .map(|idx| idx + self.pos)
    }

    pub fn find_window<F: Fn(&[u8]) -> bool>(&self, w: usize, f: F) -> Option<usize> {
        self.buf[self.pos..]
            .windows(w)
            .position(f)
            .map(|idx| idx + self.pos)
    }
}

pub trait ToStream {
    fn into_stream(self) -> ByteStream;
}

impl ToStream for String {
    fn into_stream(self) -> ByteStream {
        ByteStream::wrap(self.into_bytes())
    }
}
