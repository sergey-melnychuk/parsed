//! A small Redis-compatible server, built on a RESP parser made of `parsed` combinators
//! (see `grammar.rs`), serving GET, SET, DEL, INCR, MGET, PING and ECHO from memory.
//!
//! ```sh
//! cargo run --example resp            # listens on 127.0.0.1:6380, or pass an address
//! redis-cli -p 6380 set greeting hello
//! redis-cli -p 6380 get greeting
//! ```

mod grammar;
mod server;

use std::net::TcpListener;
use std::thread;

fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:6380".to_string());
    let listener = TcpListener::bind(&addr)?;
    let port = listener.local_addr()?.port();
    println!(
        "listening on {}; try: redis-cli -p {} set greeting hello",
        addr, port
    );

    let store = server::Store::default();
    for tcp in listener.incoming() {
        let tcp = tcp?;
        let store = store.clone();
        thread::spawn(move || {
            let peer = tcp.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            if let Err(e) = server::handle(tcp, store) {
                eprintln!("{}: {}", peer, e);
            }
        });
    }
    Ok(())
}
