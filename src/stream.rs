pub struct Mark {
    pos: usize,
}

#[derive(Debug)]
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

    pub fn put_u8(&mut self, b: u8) -> bool {
        self.put(&[b]) == 1
    }

    pub fn put_u16(&mut self, b: u16) -> bool {
        self.put(&write_u16(b)) == 16
    }

    pub fn put_u32(&mut self, b: u32) -> bool {
        self.put(&write_u32(b)) == 32
    }

    pub fn put_u64(&mut self, b: u64) -> bool {
        self.put(&write_u64(b)) == 64
    }

    pub fn put_16(&mut self, b: [u8; 16]) -> bool {
        self.put(&b) == 16
    }

    pub fn put_32(&mut self, b: [u8; 32]) -> bool {
        self.put(&b) == 32
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

    pub fn get_u8(&mut self) -> Option<u8> {
        self.get(1).map(|v| v[0])
    }

    pub fn get_u16(&mut self) -> Option<u16> {
        self.get(2).map(|v| read_u16(&v))
    }

    pub fn get_u32(&mut self) -> Option<u32> {
        self.get(4).map(|v| read_u32(&v))
    }

    pub fn get_u64(&mut self) -> Option<u64> {
        self.get(8).map(|v| read_u64(&v))
    }

    pub fn get_16(&mut self) -> Option<[u8; 16]> {
        self.get(16)
            .map(|v| {
                let mut r = [0u8; 16];
                for (i, x) in v.into_iter().enumerate() {
                    r[i] = x;
                }
                r
            })
    }

    pub fn get_32(&mut self) -> Option<[u8; 32]> {
        self.get(32)
            .map(|v| {
                let mut r = [0u8; 32];
                for (i, x) in v.into_iter().enumerate() {
                    r[i] = x;
                }
                r
            })
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

    pub fn clear(&mut self) {
        self.pos = 0;
        self.buf.clear();
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

impl AsRef<[u8]> for ByteStream {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.pos..]
    }
}

impl From<String> for ByteStream {
    fn from(s: String) -> Self {
        ByteStream::wrap(s.into_bytes())
    }
}

fn read_u16(v: &[u8]) -> u16 {
    v[0..2].iter().fold(0u16, |acc, b| (acc << 8) + (*b as u16))
}

fn read_u32(v: &[u8]) -> u32 {
    v[0..4].iter().fold(0u32, |acc, b| (acc << 8) + (*b as u32))
}

fn read_u64(v: &[u8]) -> u64 {
    v[0..8].iter().fold(0u64, |acc, b| (acc << 8) + (*b as u64))
}

fn write_u16(mut b: u16) -> [u8; 2] {
    let mut r = [0u8; 2];
    for i in (0..2).rev() {
        r[i] = (b & 0xFFu16) as u8;
        b >>= 8;
    }
    r
}

fn write_u32(mut b: u32) -> [u8; 4] {
    let mut r = [0u8; 4];
    for i in (0..4).rev() {
        r[i] = (b & 0xFFu32) as u8;
        b >>= 8;
    }
    r
}

fn write_u64(mut b: u64) -> [u8; 8] {
    let mut r = [0u8; 8];
    for i in (0..8).rev() {
        r[i] = (b & 0xFFu64) as u8;
        b >>= 8;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::QuickCheck;

    #[test]
    fn test_u64() {
        fn f(x: u64) -> bool {
            println!("x = {}", x);
            let bin = write_u64(x);
            let y = read_u64(&bin);
            x == y
        }

        QuickCheck::new().quickcheck(f as fn(u64) -> bool);
    }

    #[test]
    fn test_u32() {
        fn f(x: u32) -> bool {
            let bin = write_u32(x);
            let y = read_u32(&bin);
            x == y
        }

        QuickCheck::new().quickcheck(f as fn(u32) -> bool);
    }

    #[test]
    fn test_u16() {
        fn f(x: u16) -> bool {
            let bin = write_u16(x);
            let y = read_u16(&bin);
            x == y
        }

        QuickCheck::new().quickcheck(f as fn(u16) -> bool);
    }
}