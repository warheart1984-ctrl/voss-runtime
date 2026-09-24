//! Operator approval console.
//!
//! `console --store DIR --port-file PATH --transfer-key HEX [--auto approve|deny|cancel] [--delay SECONDS] [--port PORT]`

use std::fs;
use std::thread;
use std::time::Duration;

use voss::console::ConsoleServer;

fn main() {
    let store = argument("--store");
    let port_file = argument("--port-file");
    let transfer_key = argument("--transfer-key");
    let (store, port_file, transfer_key) = match (store, port_file, transfer_key) {
        (Some(store), Some(port_file), Some(transfer_key)) => (store, port_file, transfer_key),
        _ => {
            eprintln!(
                "usage: console --store DIR --port-file PATH --transfer-key HEX [--auto approve|deny|cancel] [--delay SECONDS] [--port PORT]"
            );
            std::process::exit(2);
        }
    };
    let auto = argument("--auto");
    let delay = argument("--delay")
        .and_then(|value| value.parse::<f64>().ok())
        .map(Duration::from_secs_f64)
        .unwrap_or_else(|| Duration::from_millis(200));
    let port = argument("--port").and_then(|value| value.parse::<u16>().ok()).unwrap_or(0);
    let transfer_key = match hex::decode(transfer_key.trim()) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("transfer key: {error}");
            std::process::exit(2);
        }
    };
    let server = match ConsoleServer::bind(&store, transfer_key, auto, delay, port) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    server.start();
    if fs::write(&port_file, format!("{}\n", server.port())).is_err() {
        eprintln!("cannot publish console port");
        server.stop();
        std::process::exit(1);
    }
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn argument(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    args.iter()
        .position(|item| item == name)
        .and_then(|index| args.get(index + 1).cloned())
}
