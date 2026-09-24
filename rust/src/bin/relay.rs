//! Write-only audit store process.
//!
//! `relay --store <dir> --keyring-dir <dir> --port-file <path> --transfer-key <hex>`

use std::fs;
use std::thread;
use std::time::Duration;

use voss::keys::KeyRing;
use voss::relay::AuditRelayServer;

fn main() {
    let store = argument("--store");
    let keyring_dir = argument("--keyring-dir");
    let port_file = argument("--port-file");
    let transfer_key = argument("--transfer-key");
    let (store, keyring_dir, port_file, transfer_key) = match (store, keyring_dir, port_file, transfer_key) {
        (Some(store), Some(keyring_dir), Some(port_file), Some(transfer_key)) => {
            (store, keyring_dir, port_file, transfer_key)
        }
        _ => {
            eprintln!("usage: relay --store DIR --keyring-dir DIR --port-file PATH --transfer-key HEX [--timeout SECONDS]");
            std::process::exit(2);
        }
    };
    let timeout = argument("--timeout")
        .and_then(|value| value.parse::<f64>().ok())
        .map(Duration::from_secs_f64)
        .unwrap_or_else(|| Duration::from_secs(15));
    let keyring = match KeyRing::load_or_create(&keyring_dir) {
        Ok(keyring) => keyring,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    let transfer_key = match hex::decode(transfer_key.trim()) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("transfer key: {error}");
            std::process::exit(2);
        }
    };
    let server = match AuditRelayServer::bind(&store, keyring, transfer_key, timeout) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    server.start();
    if fs::write(&port_file, format!("{}\n", server.port())).is_err() {
        eprintln!("cannot publish relay port");
        server.stop();
        std::process::exit(1);
    }
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn argument(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    args.iter().position(|item| item == name).and_then(|index| args.get(index + 1).cloned())
}
