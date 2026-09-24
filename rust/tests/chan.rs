//! Authenticated channel protocol.

use voss::canonical::{Json, canonical_bytes, loads_strict, new_id};
use voss::chan::{self, ChannelSession};

fn key() -> Vec<u8> {
    vec![0x11; 32]
}

fn pair() -> (ChannelSession, ChannelSession) {
    let sid = new_id("chan-");
    let host = ChannelSession::new(key(), sid.clone(), "host").unwrap();
    let adapter = ChannelSession::new(key(), sid, "adapter").unwrap();
    (host, adapter)
}

#[test]
fn round_trip_both_roles() {
    let (mut host, mut adapter) = pair();
    let hello = adapter
        .send(
            "hello",
            &Json::object([
                ("adapter", Json::string("fake")),
                ("ready", Json::Bool(true)),
            ]),
        )
        .unwrap();
    let (msg_type, msg) = host.receive(&hello).unwrap();
    assert_eq!(msg_type, "hello");
    assert_eq!(msg.get("adapter").and_then(Json::as_str), Some("fake"));

    let prompt = host
        .send(
            "prompt",
            &Json::object([
                ("prompt", Json::string("p")),
                ("session_id", Json::string("s")),
                ("principal", Json::string("w")),
            ]),
        )
        .unwrap();
    let (msg_type, msg) = adapter.receive(&prompt).unwrap();
    assert_eq!(msg_type, "prompt");
    assert_eq!(msg.get("prompt").and_then(Json::as_str), Some("p"));
}

#[test]
fn forged_mac_rejected() {
    let (mut host, mut adapter) = pair();
    let hello = adapter
        .send("hello", &Json::object([("ready", Json::Bool(true))]))
        .unwrap();
    let mut record = loads_strict(&hello).unwrap();
    let Json::Object(fields) = &mut record else {
        panic!("wire line");
    };
    fields.insert("mac".to_string(), Json::string("f".repeat(64)));
    let forged = String::from_utf8(canonical_bytes(&record).unwrap()).unwrap();
    let error = host.receive(&forged).unwrap_err();
    assert_eq!(error.code(), "denied_channel_auth");
}

#[test]
fn replay_rejected() {
    let (mut host, mut adapter) = pair();
    let hello = adapter
        .send("hello", &Json::object([("ready", Json::Bool(true))]))
        .unwrap();
    host.receive(&hello).unwrap();
    let error = host.receive(&hello).unwrap_err();
    assert_eq!(error.code(), "denied_channel_replay");
}

#[test]
fn sequence_gap_rejected() {
    let sid = new_id("chan-");
    let mut host = ChannelSession::new(key(), sid.clone(), "host").unwrap();
    let mut adapter = ChannelSession::new(key(), sid.clone(), "adapter").unwrap();
    adapter
        .send("hello", &Json::object([("ready", Json::Bool(true))]))
        .unwrap();
    let probe = chan::wire_line(
        &key(),
        &sid,
        "a2h",
        5,
        "proposal",
        &Json::object([("envelopes", Json::Array(Vec::new()))]),
    )
    .unwrap();
    let error = host.receive(&probe).unwrap_err();
    assert_eq!(error.code(), "denied_channel_sequence");
}

#[test]
fn wrong_direction_rejected() {
    let sid = new_id("chan-");
    let mut host = ChannelSession::new(key(), sid.clone(), "host").unwrap();
    let fake = chan::wire_line(
        &key(),
        &sid,
        "h2a",
        1,
        "prompt",
        &Json::object([
            ("prompt", Json::string("")),
            ("session_id", Json::string("")),
            ("principal", Json::string("")),
        ]),
    )
    .unwrap();
    let error = host.receive(&fake).unwrap_err();
    assert_eq!(error.code(), "denied_channel_wrong_direction");
}

#[test]
fn wrong_session_rejected() {
    let (mut host, _) = pair();
    let other = chan::wire_line(
        &key(),
        "chan-other",
        "a2h",
        1,
        "hello",
        &Json::object([("ready", Json::Bool(true))]),
    )
    .unwrap();
    let error = host.receive(&other).unwrap_err();
    assert_eq!(error.code(), "denied_channel_bad_session");
}

#[test]
fn adapter_cannot_send_prompt() {
    let (_, mut adapter) = pair();
    let error = adapter
        .send("prompt", &Json::object([("prompt", Json::string(""))]))
        .unwrap_err();
    assert_eq!(error.code(), "denied_channel_wrong_direction");
}

#[test]
fn bootstrap_round_trip() {
    let secret = key();
    let sid = new_id("chan-");
    let text = String::from_utf8(canonical_bytes(&chan::chan_bootstrap(&secret, &sid)).unwrap()).unwrap();
    let (loaded, loaded_sid) = chan::read_bootstrap(&text).unwrap();
    assert_eq!(loaded, secret);
    assert_eq!(loaded_sid, sid);
}

#[test]
fn tampered_bootstrap_rejected() {
    let mut data = chan::chan_bootstrap(&key(), &new_id("chan-"));
    let Json::Object(fields) = &mut data else {
        panic!("bootstrap");
    };
    fields.insert("key_hex".to_string(), Json::string("not-hex"));
    let text = String::from_utf8(canonical_bytes(&data).unwrap()).unwrap();
    let error = chan::read_bootstrap(&text).unwrap_err();
    assert_eq!(error.code(), "denied_channel_bootstrap");
}

#[test]
fn short_key_rejected() {
    let data = chan::chan_bootstrap(b"short", &new_id("chan-"));
    let text = String::from_utf8(canonical_bytes(&data).unwrap()).unwrap();
    let error = chan::read_bootstrap(&text).unwrap_err();
    assert_eq!(error.code(), "denied_channel_bootstrap");
}
