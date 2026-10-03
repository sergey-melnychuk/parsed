//! Interoperability with independent HTTP implementations over real TCP connections:
//! a `parsed` server with the ureq client, and the tiny_http server with a `parsed` client.

mod common;

use common::{Conn, binary, listen};
use parsed::http::{
    BodyDecoder, Config, Framing, Message, Request, RequestParser, Response, ResponseHeadParser,
    ResponseParser, encode_chunk, encode_last_chunk,
};
use std::io::Cursor;
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;

/// `parsed` server: answers requests on each connection until the client closes it (or
/// asks to), and reports every request it received.
fn serve(listener: std::net::TcpListener, requests: mpsc::Sender<Request>) {
    for tcp in listener.incoming() {
        let requests = requests.clone();
        thread::spawn(move || {
            let mut conn = Conn::new(tcp.unwrap(), 256, 1 << 20);
            let mut parser = RequestParser::default();
            // `None`: the client closed the connection between requests
            while let Some(req) = parser.read_from(&mut conn.bs, &mut conn.tcp).unwrap() {
                let res = respond(&req);
                conn.write(&res);
                let keep_alive = req.keep_alive();
                requests.send(req).unwrap();
                if !keep_alive {
                    return;
                }
            }
        });
    }
}

fn respond(req: &Request) -> Vec<u8> {
    let ok = || Response::new(200, "OK").with_header("Content-Type", "text/plain");
    match (req.method.as_str(), req.target.as_str()) {
        ("GET" | "HEAD", "/hello") => {
            let mut res = ok().with_body("hello, world").encode().unwrap();
            if req.method == "HEAD" {
                res.truncate(res.len() - "hello, world".len());
            }
            res
        }
        ("POST", "/echo") => ok().with_body(req.body.clone()).encode().unwrap(),
        ("GET", "/chunked") => {
            let mut res = ok()
                .with_header("Transfer-Encoding", "chunked")
                .encode()
                .unwrap();
            for part in [&b"chunked "[..], b"response ", b"body"] {
                encode_chunk(part, &mut res);
            }
            encode_last_chunk(&mut res);
            res
        }
        _ => Response::new(404, "Not Found")
            .with_body("no such thing")
            .encode()
            .unwrap(),
    }
}

#[test]
fn parsed_server_with_ureq_client() {
    let (listener, port) = listen();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || serve(listener, tx));
    let url = |path: &str| format!("http://127.0.0.1:{}{}", port, path);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();

    let mut res = agent
        .get(url("/hello"))
        .header("X-Test", "1")
        .call()
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "text/plain");
    assert_eq!(res.body_mut().read_to_string().unwrap(), "hello, world");
    let req = rx.recv().unwrap();
    assert_eq!(
        (req.method.as_str(), req.target.as_str()),
        ("GET", "/hello")
    );
    assert_eq!(
        req.header_str("host"),
        Some(format!("127.0.0.1:{}", port).as_str())
    );
    assert_eq!(req.header_str("x-test"), Some("1"));
    assert!(req.header_str("user-agent").unwrap().starts_with("ureq"));

    let res = agent.head(url("/hello")).call().unwrap();
    assert_eq!(res.headers()["content-length"], "12");
    assert_eq!(rx.recv().unwrap().method, "HEAD");

    // a body with Content-Length, larger than the server's initial buffer
    let big = binary(300_000);
    let mut res = agent.post(url("/echo")).send(&big[..]).unwrap();
    assert_eq!(res.body_mut().read_to_vec().unwrap(), big);
    let req = rx.recv().unwrap();
    assert_eq!(req.header_str("content-length"), Some("300000"));
    assert_eq!(req.body, big);

    // a streamed body: ureq sends it chunked
    let mut reader = Cursor::new(binary(50_000));
    let mut res = agent
        .post(url("/echo"))
        .send(ureq::SendBody::from_reader(&mut reader))
        .unwrap();
    assert_eq!(res.body_mut().read_to_vec().unwrap(), binary(50_000));
    let req = rx.recv().unwrap();
    assert!(req.has_token("Transfer-Encoding", "chunked"));
    assert_eq!(req.body, binary(50_000));

    // a chunked response from the server
    let mut res = agent.get(url("/chunked")).call().unwrap();
    assert_eq!(
        res.body_mut().read_to_string().unwrap(),
        "chunked response body"
    );
    rx.recv().unwrap();

    let mut res = agent.get(url("/missing")).call().unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.body_mut().read_to_string().unwrap(), "no such thing");
    rx.recv().unwrap();
}

/// tiny_http server answering `count` requests.
/// What tiny_http received: method, URL, body.
type Received = Vec<(String, String, Vec<u8>)>;

fn tiny_server(count: usize) -> (u16, thread::JoinHandle<Received>) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..count {
            let mut req = server.recv().unwrap();
            let mut body = Vec::new();
            req.as_reader().read_to_end(&mut body).unwrap();
            let method = req.method().to_string();
            let url = req.url().to_string();
            let header = |s: &str| s.parse::<tiny_http::Header>().unwrap();
            match url.as_str() {
                "/fixed" => req.respond(tiny_http::Response::from_string("fixed body")),
                // unknown length: tiny_http sends it chunked
                "/chunked" => req.respond(tiny_http::Response::new(
                    tiny_http::StatusCode(200),
                    vec![header("X-Kind: chunked")],
                    Cursor::new(binary(1 << 20)),
                    None,
                    None,
                )),
                "/empty" => req.respond(tiny_http::Response::empty(204)),
                "/echo" => req.respond(tiny_http::Response::from_data(body.clone())),
                _ => req.respond(tiny_http::Response::from_string("?").with_status_code(404)),
            }
            .unwrap();
            seen.push((method, url, body));
        }
        seen
    });
    (port, handle)
}

fn get(path: &str, port: u16) -> Request {
    Request::new("GET", path).with_header("Host", format!("127.0.0.1:{}", port))
}

#[test]
fn tiny_http_server_with_parsed_client() {
    let (port, server) = tiny_server(7);
    let mut conn = Conn::new(
        TcpStream::connect(("127.0.0.1", port)).unwrap(),
        256,
        1 << 16,
    );
    let cfg = Config {
        max_body: 4 << 20,
        ..Config::default()
    };
    let exchange = |conn: &mut Conn, req: Request| -> Response {
        conn.write(&req.encode().unwrap());
        let mut parser = ResponseParser::new(cfg, &req.method);
        parser
            .read_from(&mut conn.bs, &mut conn.tcp)
            .unwrap()
            .unwrap()
    };

    let res = exchange(&mut conn, get("/fixed", port));
    assert_eq!((res.status, res.body.as_slice()), (200, &b"fixed body"[..]));
    assert!(
        res.header_str("content-type")
            .unwrap()
            .starts_with("text/plain")
    );

    // a 1 MiB chunked body through a buffer of at most 64 KiB
    let res = exchange(&mut conn, get("/chunked", port));
    assert!(res.has_token("Transfer-Encoding", "chunked"));
    assert_eq!(res.header_str("x-kind"), Some("chunked"));
    assert_eq!(res.body, binary(1 << 20));

    // a HEAD response has no body, whatever its headers say
    let res = exchange(
        &mut conn,
        Request {
            method: "HEAD".into(),
            ..get("/fixed", port)
        },
    );
    assert_eq!((res.status, res.body.len()), (200, 0));

    let res = exchange(&mut conn, get("/empty", port));
    assert_eq!((res.status, res.body.len()), (204, 0));

    // a request body with Content-Length, and a chunked one
    let res = exchange(
        &mut conn,
        Request::new("POST", "/echo")
            .with_header("Host", "x")
            .with_body(binary(70_000)),
    );
    assert_eq!(res.body, binary(70_000));
    let mut chunked = Request::new("POST", "/echo")
        .with_header("Host", "x")
        .with_header("Transfer-Encoding", "chunked")
        .encode()
        .unwrap();
    for part in binary(10_000).chunks(3333) {
        encode_chunk(part, &mut chunked);
    }
    encode_last_chunk(&mut chunked);
    conn.write(&chunked);
    let mut parser = ResponseParser::new(cfg, "POST");
    let res = parser
        .read_from(&mut conn.bs, &mut conn.tcp)
        .unwrap()
        .unwrap();
    assert_eq!(res.body, binary(10_000));

    // streaming: the head first, then the body in pieces, in constant memory
    conn.write(
        &get("/chunked", port)
            .with_header("Connection", "close")
            .encode()
            .unwrap(),
    );
    let mut heads = ResponseHeadParser::new(cfg, "GET");
    let (res, framing) = heads
        .read_from(&mut conn.bs, &mut conn.tcp)
        .unwrap()
        .unwrap();
    assert_eq!((res.status, framing), (200, Framing::Chunked));
    let mut decoder = BodyDecoder::new(framing, &cfg);
    let mut body = Vec::new();
    while !decoder.is_done() {
        let piece = conn.parse(|bs| decoder.decode(bs).map(|p| p.map(<[u8]>::to_vec)));
        if let Some(piece) = piece.unwrap() {
            body.extend(piece);
        }
    }
    assert_eq!(body, binary(1 << 20));

    let seen = server.join().unwrap();
    assert_eq!(seen[4].2, binary(70_000));
    assert_eq!(
        seen[5].2,
        binary(10_000),
        "tiny_http decoded our chunked request"
    );
}

#[test]
fn tiny_http_pipelined() {
    let (port, server) = tiny_server(3);
    let mut conn = Conn::new(
        TcpStream::connect(("127.0.0.1", port)).unwrap(),
        64,
        1 << 16,
    );
    let mut wire = Vec::new();
    for path in ["/fixed", "/empty", "/fixed"] {
        get(path, port).encode_into(&mut wire).unwrap();
    }
    conn.write(&wire);
    let mut parser = ResponseParser::new(Config::default(), "GET");
    let statuses: Vec<u16> = (0..3)
        .map(|_| {
            parser
                .read_from(&mut conn.bs, &mut conn.tcp)
                .unwrap()
                .unwrap()
                .status
        })
        .collect();
    assert_eq!(statuses, vec![200, 204, 200]);
    server.join().unwrap();
}
