//! A Redis-compatible server on the RESP grammar: a few commands over an in-memory store.

use super::grammar::{self, Value};
use parsed::matcher::{ReadError, Resumable};
use parsed::stream::ByteStream;
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

/// The key-value store shared by all connections.
pub type Store = Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>;

/// Serve one client until it disconnects.
pub fn handle(tcp: TcpStream, store: Store) -> Result<(), ReadError> {
    let mut reader = tcp.try_clone()?;
    let mut writer = tcp;
    // grows as needed: bulk strings are accumulated as they arrive, so only the other
    // parts of a value must fit into the buffer at once
    let mut bs = ByteStream::growable(4 << 10, 64 << 10);
    let mut parser = Resumable::new(grammar::value(0));
    let mut out = Vec::new();
    loop {
        let reply = match parser.read_from(&mut bs, &mut reader) {
            Ok(Some(request)) => execute(request, &store),
            Ok(None) => return Ok(()),
            Err(ReadError::Parse(e)) => {
                // like Redis: report the protocol error, then close the connection
                let error = Value::Error(format!("ERR Protocol error: {}", e));
                grammar::encode(&error, &mut out);
                writer.write_all(&out)?;
                return Err(ReadError::Parse(e));
            }
            Err(e) => return Err(e),
        };
        grammar::encode(&reply, &mut out);
        // pipelined requests: answer them all with one write
        if bs.remaining() == 0 {
            writer.write_all(&out)?;
            out.clear();
        }
    }
}

fn error(message: impl Into<String>) -> Value {
    Value::Error(message.into())
}

/// Execute a command (an array of bulk strings).
pub fn execute(request: Value, store: &Store) -> Value {
    let Value::Array(Some(items)) = request else {
        return error("ERR expected a command (an array of bulk strings)");
    };
    let mut args = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Bulk(Some(arg)) => args.push(arg),
            _ => return error("ERR expected a command (an array of bulk strings)"),
        }
    }
    let Some((name, args)) = args.split_first() else {
        return error("ERR empty command");
    };
    let name = String::from_utf8_lossy(name).to_lowercase();
    let mut store = store.lock().unwrap();
    match (name.as_str(), args) {
        ("ping", []) => Value::Simple("PONG".into()),
        ("ping" | "echo", [message]) => Value::Bulk(Some(message.clone())),
        ("get", [key]) => Value::Bulk(store.get(key).cloned()),
        ("set", [key, value]) => {
            store.insert(key.clone(), value.clone());
            Value::Simple("OK".into())
        }
        ("del", keys) if !keys.is_empty() => {
            Value::Integer(keys.iter().filter(|k| store.remove(*k).is_some()).count() as i64)
        }
        ("incr", [key]) => {
            let current = store.get(key).map(|v| {
                std::str::from_utf8(v)
                    .ok()
                    .and_then(|v| v.parse::<i64>().ok())
            });
            match current.unwrap_or(Some(0)).and_then(|n| n.checked_add(1)) {
                Some(n) => {
                    store.insert(key.clone(), n.to_string().into_bytes());
                    Value::Integer(n)
                }
                None => error("ERR value is not an integer or out of range"),
            }
        }
        ("mget", keys) if !keys.is_empty() => Value::Array(Some(
            keys.iter()
                .map(|k| Value::Bulk(store.get(k).cloned()))
                .collect(),
        )),
        // sent by clients on connect
        ("client", [sub, ..]) if sub.eq_ignore_ascii_case(b"setinfo") => Value::Simple("OK".into()),
        ("command", _) => Value::Array(Some(Vec::new())),
        ("ping" | "echo" | "get" | "set" | "del" | "incr" | "mget" | "client", _) => error(
            format!("ERR wrong number of arguments for '{}' command", name),
        ),
        _ => error(format!("ERR unknown command '{}'", name)),
    }
}
