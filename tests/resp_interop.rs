//! The RESP example (`examples/resp/`) against independent Redis implementations, over
//! real TCP connections: a client on its grammar with an embedded mini-redis server, and
//! the `redis` crate's client with the example's server.

mod common;

#[path = "../examples/resp/grammar.rs"]
mod grammar;
#[path = "../examples/resp/server.rs"]
mod server;

use common::{binary, listen};
use grammar::{Value, encode};
use parsed::matcher::{Boxed, Resumable};
use parsed::stream::ByteStream;
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;

/// Start an embedded mini-redis server, returning its port.
fn mini_redis() -> u16 {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap().port()).unwrap();
            mini_redis::server::run(listener, std::future::pending::<()>())
                .await
                .unwrap();
        });
    });
    rx.recv().unwrap()
}

/// A command, as clients send it: an array of bulk strings.
fn command(args: &[&[u8]]) -> Value {
    Value::Array(Some(
        args.iter().map(|a| Value::Bulk(Some(a.to_vec()))).collect(),
    ))
}

struct Client {
    tcp: TcpStream,
    bs: ByteStream<'static>,
    parser: Resumable<Boxed<Value>, Value>,
}

impl Client {
    // the buffer grows to at most 64 bytes: most values are parsed resumably
    fn connect(port: u16) -> Client {
        Client {
            tcp: TcpStream::connect(("127.0.0.1", port)).unwrap(),
            bs: ByteStream::growable(8, 64),
            parser: Resumable::new(grammar::value(0)),
        }
    }

    fn send(&mut self, args: &[&[u8]]) {
        let mut wire = Vec::new();
        encode(&command(args), &mut wire);
        std::io::Write::write_all(&mut self.tcp, &wire).unwrap();
    }

    fn receive(&mut self) -> Value {
        self.parser
            .read_from(&mut self.bs, &mut self.tcp)
            .unwrap()
            .expect("a reply")
    }

    fn call(&mut self, args: &[&[u8]]) -> Value {
        self.send(args);
        self.receive()
    }
}

fn bulk(data: &[u8]) -> Value {
    Value::Bulk(Some(data.to_vec()))
}

#[test]
fn parsed_client_with_mini_redis() {
    let port = mini_redis();
    let mut client = Client::connect(port);

    assert_eq!(
        client.call(&[b"SET", b"greeting", b"hello"]),
        Value::Simple("OK".into())
    );
    assert_eq!(client.call(&[b"GET", b"greeting"]), bulk(b"hello"));
    assert_eq!(client.call(&[b"GET", b"missing"]), Value::Bulk(None));

    // a value much larger than the client's buffer
    let big = binary(1 << 20);
    assert_eq!(
        client.call(&[b"SET", b"big", &big]),
        Value::Simple("OK".into())
    );
    assert_eq!(client.call(&[b"GET", b"big"]), bulk(&big));

    assert!(matches!(client.call(&[b"NOPE"]), Value::Error(e) if e.contains("unknown command")));

    // pipelined commands
    client.send(&[b"SET", b"a", b"1"]);
    client.send(&[b"SET", b"b", b"2"]);
    client.send(&[b"GET", b"a"]);
    client.send(&[b"GET", b"b"]);
    let replies: Vec<Value> = (0..4).map(|_| client.receive()).collect();
    assert_eq!(replies[2..], [bulk(b"1"), bulk(b"2")]);

    // pub/sub: the server pushes arrays of mixed types
    let mut subscriber = Client::connect(port);
    let confirmation = subscriber.call(&[b"SUBSCRIBE", b"news"]);
    assert_eq!(
        confirmation,
        Value::Array(Some(vec![
            bulk(b"subscribe"),
            bulk(b"news"),
            Value::Integer(1)
        ]))
    );
    assert_eq!(
        client.call(&[b"PUBLISH", b"news", b"extra!"]),
        Value::Integer(1)
    );
    assert_eq!(
        subscriber.receive(),
        Value::Array(Some(vec![bulk(b"message"), bulk(b"news"), bulk(b"extra!")]))
    );
    assert_eq!(
        client.call(&[b"PUBLISH", b"other", b"x"]),
        Value::Integer(0)
    );
}

#[test]
fn redis_client_with_parsed_server() {
    // the example's server
    let (listener, port) = listen();
    thread::spawn(move || {
        let store = server::Store::default();
        for tcp in listener.incoming() {
            let store = store.clone();
            thread::spawn(move || server::handle(tcp.unwrap(), store).unwrap());
        }
    });
    let client = redis::Client::open(format!("redis://127.0.0.1:{}/", port)).unwrap();
    let mut con = client.get_connection().unwrap();

    let pong: String = redis::cmd("PING").query(&mut con).unwrap();
    assert_eq!(pong, "PONG");
    let echo: String = redis::cmd("ECHO").arg("hi there").query(&mut con).unwrap();
    assert_eq!(echo, "hi there");

    redis::cmd("SET").arg("k").arg("v").exec(&mut con).unwrap();
    let v: String = redis::cmd("GET").arg("k").query(&mut con).unwrap();
    assert_eq!(v, "v");
    let missing: Option<String> = redis::cmd("GET").arg("nothing").query(&mut con).unwrap();
    assert_eq!(missing, None);

    let n: i64 = redis::cmd("INCR").arg("counter").query(&mut con).unwrap();
    assert_eq!(n, 1);
    let n: i64 = redis::cmd("INCR").arg("counter").query(&mut con).unwrap();
    assert_eq!(n, 2);

    // an array reply with a nil element
    let values: Vec<Option<String>> = redis::cmd("MGET")
        .arg("k")
        .arg("nothing")
        .arg("counter")
        .query(&mut con)
        .unwrap();
    assert_eq!(values, vec![Some("v".into()), None, Some("2".into())]);

    // a value larger than the server's buffer
    let big = binary(1 << 20);
    redis::cmd("SET")
        .arg("big")
        .arg(&big)
        .exec(&mut con)
        .unwrap();
    let got: Vec<u8> = redis::cmd("GET").arg("big").query(&mut con).unwrap();
    assert_eq!(got, big);

    // a pipeline: the server gets several commands in one read
    let (a, b, deleted): (String, i64, i64) = redis::pipe()
        .cmd("SET")
        .arg("p")
        .arg("1")
        .ignore()
        .cmd("GET")
        .arg("p")
        .cmd("INCR")
        .arg("p")
        .cmd("DEL")
        .arg("p")
        .arg("k")
        .arg("nothing")
        .query(&mut con)
        .unwrap();
    assert_eq!((a.as_str(), b, deleted), ("1", 2, 2));

    let err = redis::cmd("FLUSHALL").exec(&mut con).unwrap_err();
    assert!(err.to_string().contains("unknown command"), "{}", err);
    let err = redis::cmd("GET").exec(&mut con).unwrap_err();
    assert!(
        err.to_string().contains("wrong number of arguments"),
        "{}",
        err
    );
    let err = redis::cmd("SET")
        .arg("text")
        .arg("x")
        .exec(&mut con)
        .and_then(|_| redis::cmd("INCR").arg("text").query::<i64>(&mut con));
    assert!(err.unwrap_err().to_string().contains("not an integer"));
}
