//! Adversarial channel peer for transport tests.
//!
//! `VOSS_EVIL_MODE` selects the attack. The runtime provisions the bootstrap
//! file the same way it does for a real worker.

use std::io::{self, BufRead, Write};
use std::path::Path;

use voss::canonical::{Json, canonical_bytes, loads_strict};
use voss::chan::{self, ChannelSession, MAX_LINE};

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let mode = std::env::var("VOSS_EVIL_MODE").unwrap_or_else(|_| "valid".to_string());
    let path = match std::env::var("VOSS_CHANNEL_BOOTSTRAP") {
        Ok(path) if !path.is_empty() => path,
        _ => {
            eprintln!("error: denied_channel_bootstrap");
            return 2;
        }
    };
    let (key, sid) = match chan::consume_bootstrap(Path::new(&path)) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("error: {}", error.code());
            return 2;
        }
    };
    let mut session = match ChannelSession::new(key.clone(), sid.clone(), "adapter") {
        Ok(session) => session,
        Err(error) => {
            eprintln!("error: {}", error.code());
            return 2;
        }
    };
    if mode == "handshake-forged-mac" {
        let hello = match session.send("hello", &hello_body()) {
            Ok(line) => line,
            Err(error) => {
                eprintln!("error: {}", error.code());
                return 3;
            }
        };
        println!("{}", corrupt_mac(&hello));
        let _ = io::stdout().flush();
        return 0;
    }
    let valid_hello = match session.send("hello", &hello_body()) {
        Ok(line) => line,
        Err(error) => {
            eprintln!("error: {}", error.code());
            return 3;
        }
    };
    println!("{valid_hello}");
    let _ = io::stdout().flush();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match session.receive(line) {
            Err(_) => return 3,
            Ok((msg_type, _)) if msg_type != "prompt" => continue,
            Ok(_) => {}
        }
        let reply = match mode.as_str() {
            "reply-forged-mac" => {
                let proposal = match session.send("proposal", &empty_proposal()) {
                    Ok(line) => line,
                    Err(_) => return 3,
                };
                corrupt_mac(&proposal)
            }
            "reply-replay" => valid_hello.clone(),
            "reply-skip-seq" => match chan::wire_line(&key, &sid, "a2h", 3, "proposal", &empty_proposal()) {
                Ok(line) => line,
                Err(_) => return 3,
            },
            "reply-wrong-direction" => {
                let msg = Json::object([
                    ("prompt", Json::string("")),
                    ("session_id", Json::string("")),
                    ("principal", Json::string("")),
                ]);
                match chan::wire_line(&key, &sid, "h2a", 1, "prompt", &msg) {
                    Ok(line) => line,
                    Err(_) => return 3,
                }
            }
            "reply-oversize" => "x".repeat(MAX_LINE + 1),
            _ => match session.send("proposal", &empty_proposal()) {
                Ok(line) => line,
                Err(_) => return 3,
            },
        };
        println!("{reply}");
        let _ = io::stdout().flush();
        return 0;
    }
    0
}

fn hello_body() -> Json {
    Json::object([
        ("adapter", Json::string("evil")),
        ("ready", Json::Bool(true)),
    ])
}

fn empty_proposal() -> Json {
    Json::object([("envelopes", Json::Array(Vec::new()))])
}

fn corrupt_mac(wire_line: &str) -> String {
    let Ok(mut record) = loads_strict(wire_line) else {
        return wire_line.to_string();
    };
    let Json::Object(fields) = &mut record else {
        return wire_line.to_string();
    };
    fields.insert("mac".to_string(), Json::string("0".repeat(64)));
    canonical_bytes(&record)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| wire_line.to_string())
}
