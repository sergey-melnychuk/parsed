//! Interoperability with tungstenite, an independent WebSocket implementation, over real
//! TCP connections: a `parsed` server with a tungstenite client, and a tungstenite
//! server with a `parsed` client.

mod common;

use common::{Conn, binary, listen, text};
use parsed::http::{Config, RequestParser, ResponseParser};
use parsed::ws::{CloseFrame, Message, MessageConfig, MessageReader, handshake};
use std::net::TcpStream;
use std::thread;
use tungstenite::protocol::CloseFrame as TCloseFrame;
use tungstenite::protocol::frame::coding::CloseCode;

type TMessage = tungstenite::Message;

fn read_message(conn: &mut Conn, reader: &mut MessageReader) -> Option<Message> {
    reader.read_from(&mut conn.bs, &mut conn.tcp).unwrap()
}

/// `parsed` server: handshake, then echo data messages (in fragments of 1000 bytes),
/// answer pings, and echo the close frame. Returns the messages received.
fn serve(tcp: TcpStream) -> Vec<Message> {
    let mut conn = Conn::new(tcp, 1024, 8 << 10);
    let mut requests = RequestParser::default();
    let req = requests
        .read_from(&mut conn.bs, &mut conn.tcp)
        .unwrap()
        .unwrap();
    let res = handshake::accept(&req).unwrap();
    conn.write(&res.encode().unwrap());

    let mut reader = MessageReader::new(MessageConfig::server());
    let mut received = Vec::new();
    loop {
        let msg = read_message(&mut conn, &mut reader).unwrap();
        received.push(msg.clone());
        match msg {
            Message::Text(_) | Message::Binary(_) => {
                for frame in msg.fragments(1000).unwrap() {
                    conn.write(&frame.encode().unwrap());
                }
            }
            Message::Ping(payload) => conn.write(&Message::Pong(payload).encode(None).unwrap()),
            Message::Pong(_) => {}
            Message::Close(close) => {
                conn.write(&Message::Close(close).encode(None).unwrap());
                return received;
            }
        }
    }
}

#[test]
fn parsed_server_with_tungstenite_client() {
    let (listener, port) = listen();
    let server = thread::spawn(move || serve(listener.accept().unwrap().0));

    let (mut client, response) =
        tungstenite::connect(format!("ws://127.0.0.1:{}/chat", port)).unwrap();
    assert_eq!(response.status(), 101);

    let big_text = text(100_000);
    let big_binary = binary(200_000);
    client.send(TMessage::text("hello")).unwrap();
    client.send(TMessage::text(big_text.clone())).unwrap();
    client.send(TMessage::binary(big_binary.clone())).unwrap();
    client
        .send(TMessage::Ping(b"ping!".to_vec().into()))
        .unwrap();

    let mut replies = Vec::new();
    while replies.len() < 4 {
        replies.push(client.read().unwrap());
    }
    assert_eq!(replies[0], TMessage::text("hello"));
    assert_eq!(replies[1], TMessage::text(big_text.clone()));
    assert_eq!(replies[2], TMessage::binary(big_binary.clone()));
    assert_eq!(replies[3], TMessage::Pong(b"ping!".to_vec().into()));

    client
        .close(Some(TCloseFrame {
            code: CloseCode::Normal,
            reason: "bye".into(),
        }))
        .unwrap();
    // the server echoes the close frame, then the closing handshake is complete
    loop {
        match client.read() {
            Ok(TMessage::Close(Some(frame))) => {
                assert_eq!(
                    (u16::from(frame.code), frame.reason.as_str()),
                    (1000, "bye")
                )
            }
            Ok(other) => panic!("unexpected {:?}", other),
            Err(tungstenite::Error::ConnectionClosed) => break,
            Err(e) => panic!("{}", e),
        }
    }

    let received = server.join().unwrap();
    assert_eq!(
        received,
        vec![
            Message::Text("hello".into()),
            Message::Text(big_text),
            Message::Binary(big_binary),
            Message::Ping(b"ping!".to_vec()),
            Message::Close(Some(CloseFrame {
                code: 1000,
                reason: "bye".into(),
            })),
        ]
    );
}

#[test]
fn tungstenite_server_with_parsed_client() {
    let (listener, port) = listen();
    // tungstenite server: echo data messages until the client closes
    let server = thread::spawn(move || {
        let mut ws = tungstenite::accept(listener.accept().unwrap().0).unwrap();
        loop {
            match ws.read() {
                Ok(msg @ (TMessage::Text(_) | TMessage::Binary(_))) => ws.send(msg).unwrap(),
                // pings are answered by tungstenite itself
                Ok(_) => {}
                Err(tungstenite::Error::ConnectionClosed) => return,
                Err(e) => panic!("{}", e),
            }
        }
    });

    let mut conn = Conn::new(
        TcpStream::connect(("127.0.0.1", port)).unwrap(),
        1024,
        8 << 10,
    );
    let host = format!("127.0.0.1:{}", port);
    let req = handshake::request(&host, "/chat", *b"0123456789abcdef");
    let key = req
        .headers
        .iter()
        .find(|h| h.name == "Sec-WebSocket-Key")
        .unwrap()
        .value
        .clone();
    conn.write(&req.encode().unwrap());
    let mut responses = ResponseParser::new(Config::default(), "GET");
    let res = responses
        .read_from(&mut conn.bs, &mut conn.tcp)
        .unwrap()
        .unwrap();
    handshake::validate_response(&res, &key).unwrap();

    // client frames must be masked, with a fresh key each (a counter is enough here)
    let mut masks = (0u32..).map(|i| (i.wrapping_mul(0x9E37_79B9)).to_be_bytes());
    let mut send = |conn: &mut Conn, msg: &Message, fragment: usize| {
        for frame in msg.fragments(fragment).unwrap() {
            conn.write(&frame.masked(masks.next().unwrap()).encode().unwrap());
        }
    };

    let mut reader = MessageReader::new(MessageConfig::client());
    let big_text = Message::Text(text(100_000));
    let big_binary = Message::Binary(binary(200_000));
    for (msg, fragment) in [
        (Message::Text("hello".into()), 1000),
        (big_text, 777),
        (big_binary, 65536),
        (Message::Text(text(10)), 1),
    ] {
        send(&mut conn, &msg, fragment);
        assert_eq!(read_message(&mut conn, &mut reader).unwrap(), msg);
    }

    send(&mut conn, &Message::Ping(b"ping?".to_vec()), 125);
    assert_eq!(
        read_message(&mut conn, &mut reader).unwrap(),
        Message::Pong(b"ping?".to_vec())
    );

    let close = Message::Close(Some(CloseFrame {
        code: 1000,
        reason: "done".into(),
    }));
    send(&mut conn, &close, 125);
    match read_message(&mut conn, &mut reader).unwrap() {
        Message::Close(Some(frame)) => assert_eq!(frame.code, 1000),
        other => panic!("unexpected {:?}", other),
    }
    // the closing handshake is complete: no more messages
    assert_eq!(read_message(&mut conn, &mut reader), None);
    server.join().unwrap();
}
