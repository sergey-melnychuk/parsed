#[macro_use]
extern crate bencher;
use bencher::Bencher;

use parsed::matcher::{Boxed, Resumable};
use parsed::parser::{
    Applicator, Either, Matcher, bytes, decimal, get_u8, integer, lazy, length_prefixed, preceded,
    repeat, rest, separated, tag, take_until, times, unit, varint,
};
use parsed::stream::ByteStream;

fn lines_input() -> Vec<u8> {
    (0..1000)
        .flat_map(|i| format!("line number {}\r\n", i).into_bytes())
        .collect()
}

fn lines() -> impl Matcher<Vec<Vec<u8>>> {
    repeat(take_until(b"\r\n").then_ignore(tag(b"\r\n")))
}

fn crlf_lines(b: &mut Bencher) {
    let input = lines_input();
    b.iter(|| {
        let v = ByteStream::borrow(&input).apply(lines()).unwrap();
        assert_eq!(v.len(), 1000);
    });
    b.bytes = input.len() as u64;
}

// the same, resumed over 64-byte chunks
fn crlf_lines_resumable(b: &mut Bencher) {
    let input = lines_input();
    let line = || take_until(b"\r\n").then_ignore(tag(b"\r\n"));
    let mut parser = Resumable::new(line());
    b.iter(|| {
        let mut bs = ByteStream::with_capacity(128);
        let mut n = 0;
        for chunk in input.chunks(64) {
            bs.pull();
            bs.put(chunk);
            while parser.parse(&mut bs).is_ok() {
                n += 1;
            }
        }
        assert_eq!(n, 1000);
    });
    b.bytes = input.len() as u64;
}

fn number_list(b: &mut Bencher) {
    let input: Vec<u8> = (0..1000)
        .map(|i| (i * 7919).to_string())
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes();
    b.iter(|| {
        let v = ByteStream::borrow(&input)
            .apply(separated(decimal(), tag(b",")))
            .unwrap();
        assert_eq!(v.len(), 1000);
    });
    b.bytes = input.len() as u64;
}

// type byte, varint length, payload
fn tlv_input() -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..1000u32 {
        let payload = vec![i as u8; (i % 200) as usize];
        out.push((i % 4) as u8);
        let mut n = payload.len() as u64;
        loop {
            let byte = (n & 0x7F) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out.extend(payload);
    }
    out
}

fn tlv(b: &mut Bencher) {
    let input = tlv_input();
    let record = || get_u8().then(length_prefixed(varint(), rest));
    b.iter(|| {
        let v = ByteStream::borrow(&input).apply(repeat(record())).unwrap();
        assert_eq!(v.len(), 1000);
    });
    b.bytes = input.len() as u64;
}

#[derive(Debug)]
#[allow(dead_code)]
enum Value {
    Int(i64),
    Bulk(Vec<u8>),
    Array(Vec<Value>),
}

fn resp(depth: usize) -> Boxed<Value> {
    let int = preceded(tag(b":"), integer().then_ignore(tag(b"\r\n"))).map(Value::Int);
    let bulk = preceded(tag(b"$"), decimal().then_ignore(tag(b"\r\n")))
        .then_with(|n| bytes(*n as usize).then_ignore(tag(b"\r\n")))
        .map(|(_, v)| Value::Bulk(v));
    let array = preceded(tag(b"*"), decimal().then_ignore(tag(b"\r\n")))
        .then_with(move |n| {
            if depth > 8 {
                Either::Left(unit(Vec::new))
            } else {
                Either::Right(times(*n as usize, lazy(move || resp(depth + 1))))
            }
        })
        .map(|(_, v)| Value::Array(v));
    int.or(bulk).or(array).boxed()
}

fn resp_commands(b: &mut Bencher) {
    let cmd = b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n";
    let input: Vec<u8> = cmd.iter().copied().cycle().take(cmd.len() * 100).collect();
    b.iter(|| {
        let v = ByteStream::borrow(&input).apply(repeat(resp(0))).unwrap();
        assert_eq!(v.len(), 100);
    });
    b.bytes = input.len() as u64;
}

benchmark_group!(
    core,
    crlf_lines,
    crlf_lines_resumable,
    number_list,
    tlv,
    resp_commands
);
benchmark_main!(core);
