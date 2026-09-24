//! Adversarial worker for the temporal oracle.
//!
//! Same authenticated channel as the real adapter, and it never executes.
//! `VOSS_STALL_SECONDS` delays each proposal. `VOSS_BIG_VOLUME=1` pads the
//! proposal past the 16 KiB exchange cap while staying under the channel
//! line limit.

use std::io::{self, BufRead, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use voss::canonical::{Json, new_id};
use voss::chan::{self, ChannelSession, MAX_LINE};

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let path = match std::env::var("VOSS_CHANNEL_BOOTSTRAP") {
        Ok(path) if !path.is_empty() => path,
        _ => {
            eprintln!("error: no channel bootstrap; refusing unauthenticated mode");
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
    let mut session = match ChannelSession::new(key, sid, "adapter") {
        Ok(session) => session,
        Err(error) => {
            eprintln!("error: {}", error.code());
            return 2;
        }
    };
    let hello = Json::object([
        ("adapter", Json::string("voss.adversarial-stall")),
        ("ready", Json::Bool(true)),
    ]);
    let Ok(hello_line) = session.send("hello", &hello) else {
        eprintln!("error: denied_channel_auth");
        return 3;
    };
    println!("{hello_line}");
    let _ = io::stdout().flush();

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    loop {
        let line = match read_capped(&mut reader) {
            ReadEvent::Line(line) => line,
            ReadEvent::Empty => continue,
            ReadEvent::Eof => break,
            ReadEvent::Oversize | ReadEvent::Failed => {
                eprintln!("error: denied_channel_oversize");
                return 3;
            }
        };
        let (msg_type, msg) = match session.receive(&line) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("error: {}", error.code());
                return 3;
            }
        };
        if msg_type == "hello_ok" {
            continue;
        }
        if msg_type != "prompt" {
            continue;
        }
        let stall = stall_seconds();
        if stall > 0.0 {
            thread::sleep(Duration::from_secs_f64(stall));
        }
        let session_id = msg.get("session_id").and_then(Json::as_str).unwrap_or("");
        let principal = msg.get("principal").and_then(Json::as_str).unwrap_or("");
        let payload = if std::env::var("VOSS_BIG_VOLUME").ok().as_deref() == Some("1") {
            Json::object([("noise", Json::string("x".repeat(40_000)))])
        } else {
            Json::empty_object()
        };
        let envelopes = vec![Json::object([
            ("action", Json::string("workspace.read")),
            ("constraints", Json::empty_object()),
            ("payload", payload),
            ("principal", Json::string(principal)),
            ("request_id", Json::string(new_id("req-"))),
            ("resource", Json::object([("path", Json::string("notes.txt"))])),
            ("session_id", Json::string(session_id)),
            ("version", Json::string("1")),
        ])];
        let proposal = Json::object([("envelopes", Json::Array(envelopes))]);
        let Ok(wire) = session.send("proposal", &proposal) else {
            eprintln!("error: denied_channel_auth");
            return 3;
        };
        println!("{wire}");
        let _ = io::stdout().flush();
    }
    0
}

fn stall_seconds() -> f64 {
    std::env::var("VOSS_STALL_SECONDS")
        .ok()
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(0.0)
}

enum ReadEvent {
    Line(String),
    Empty,
    Eof,
    Oversize,
    Failed,
}

fn read_capped(reader: &mut impl BufRead) -> ReadEvent {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                if raw.is_empty() {
                    return ReadEvent::Eof;
                }
                break;
            }
            Ok(_) => {
                raw.push(byte[0]);
                if raw.len() > MAX_LINE {
                    return ReadEvent::Oversize;
                }
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(_) => return ReadEvent::Failed,
        }
    }
    while raw.last() == Some(&b'\n') || raw.last() == Some(&b'\r') {
        raw.pop();
    }
    match String::from_utf8(raw) {
        Ok(line) if line.is_empty() => ReadEvent::Empty,
        Ok(line) => ReadEvent::Line(line),
        Err(_) => ReadEvent::Failed,
    }
}
