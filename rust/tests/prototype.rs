use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use voss::KeyRing;
use voss::canonical::{Json, canonical_bytes, loads_strict, sha256_hex};
use voss::policy::{
    DECISION_ALLOW, DECISION_DENY, PolicyEngine, PolicyFields, PolicyLoader, Rule,
    build_policy_body, package_policy,
};
use voss::protocol::{CanonicalRequest, RequestNormalizer, action_class, bind};

fn workspace() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("voss-proto-{nanos}"));
    fs::create_dir_all(dir.join("allowed")).unwrap();
    fs::create_dir_all(dir.join("other")).unwrap();
    fs::write(dir.join("allowed").join("a.txt"), b"alpha").unwrap();
    fs::write(dir.join("other").join("b.txt"), b"beta").unwrap();
    dir
}

fn envelope(action: &str, path: &str) -> Json {
    Json::object([
        ("version", Json::string("1")),
        ("request_id", Json::string("req-1")),
        ("session_id", Json::string("sess-1")),
        ("principal", Json::string("worker-1")),
        ("action", Json::string(action)),
        ("resource", Json::object([("path", Json::string(path))])),
        ("payload", Json::empty_object()),
        ("constraints", Json::object([("size_max", Json::Int(100))])),
    ])
}

fn fields_covering() -> PolicyFields {
    PolicyFields {
        valid_from: "2020-01-01T00:00:00+00:00".to_string(),
        valid_until: "2099-01-01T00:00:00+00:00".to_string(),
        created_at: "2026-09-23T13:00:00+00:00".to_string(),
        ..PolicyFields::default()
    }
}

#[test]
fn approval_binding_matches_the_python_digest() {
    let expires_at = match loads_strict("1758630000.123456").unwrap() {
        Json::Float(value) => value,
        other => panic!("expected float, got {other:?}"),
    };
    let request = bind(
        &CanonicalRequest {
            version: "1".to_string(),
            request_id: "req-1".to_string(),
            session_id: "sess-1".to_string(),
            principal: "worker-1".to_string(),
            action: "workspace.read".to_string(),
            resource: Json::object([("path", Json::string(r"C:\work\a.txt"))]),
            payload: Json::empty_object(),
            constraints: Json::object([("size_max", Json::Int(100))]),
            payload_digest: sha256_hex(&Json::empty_object()).unwrap(),
            nonce: String::new(),
            expires_at: 0.0,
        },
        "abc",
        expires_at,
    );
    assert_eq!(
        request.digest().unwrap(),
        "b7e6b285904923cdaf2ccedf6e68048ac9e9ffbf9368a4f40466e606a3efaac5"
    );
    assert_eq!(
        request.binding_digest("1.0.0").unwrap(),
        "00058dedb1c5a31a8fd28dfdce4135e26ec97e138d8aa4ebb82ee47d9b35013a"
    );
    assert_eq!(action_class("workspace.read"), "A0");
    assert_eq!(action_class("workspace.write"), "A1");
    assert_eq!(action_class("external.send_mock"), "A2");
}

#[test]
fn policy_is_default_deny_and_fail_closed() {
    let root = workspace();
    let keyring = KeyRing::new(vec![b'p'; 32], vec![b'a'; 32]).unwrap();
    let allowed = root.join("allowed");
    let mut read = Rule::allow("workspace.read");
    read.resource_prefix = Some(Json::object([(
        "path_prefix",
        Json::string(allowed.to_str().unwrap()),
    )]));
    let send = Rule::require_approval("external.send_mock");
    let body = build_policy_body(&[read, send], &fields_covering());
    let package = package_policy(&body, &keyring).unwrap();
    let loader = PolicyLoader::with_clock(keyring.clone(), || 1_758_630_000.0);
    let bundle = loader.load_and_verify(&package).unwrap();
    let engine = PolicyEngine::new(bundle);

    let normalizer = RequestNormalizer::new(
        &root,
        ["workspace.read", "workspace.write", "external.send_mock"],
    )
    .unwrap();
    let allowed_request = normalizer
        .normalize(
            &envelope(
                "workspace.read",
                root.join("allowed").join("a.txt").to_str().unwrap(),
            ),
            "worker-1",
        )
        .unwrap();
    let decision = engine.evaluate(&allowed_request);
    assert_eq!(decision.decision, DECISION_ALLOW);
    assert_eq!(decision.reason, "policy_allowed");

    let other = normalizer
        .normalize(
            &envelope(
                "workspace.read",
                root.join("other").join("b.txt").to_str().unwrap(),
            ),
            "worker-1",
        )
        .unwrap();
    let decision = engine.evaluate(&other);
    assert_eq!(decision.decision, DECISION_DENY);
    assert_eq!(decision.reason, "denied_policy_no_rule");

    let dotted = root.join("allowed").join("..").join("other").join("b.txt");
    let dotted_request = normalizer
        .normalize(
            &envelope("workspace.read", dotted.to_str().unwrap()),
            "worker-1",
        )
        .unwrap();
    let decision = engine.evaluate(&dotted_request);
    assert_eq!(decision.decision, DECISION_DENY);
    assert_eq!(decision.reason, "denied_policy_no_rule");

    let outside = std::env::temp_dir().join("voss-outside-not-in-workspace.txt");
    let error = normalizer
        .normalize(
            &envelope("workspace.read", outside.to_str().unwrap()),
            "worker-1",
        )
        .unwrap_err();
    assert!(error.message().contains("escapes"), "{}", error.message());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn unsigned_conflicting_and_approvalless_policy_is_rejected() {
    let keyring = KeyRing::new(vec![1u8; 32], vec![2u8; 32]).unwrap();
    let other = KeyRing::new(vec![3u8; 32], vec![4u8; 32]).unwrap();
    let fields = fields_covering();
    let body = build_policy_body(
        &[
            Rule::allow("workspace.read"),
            Rule::require_approval("workspace.write"),
        ],
        &fields,
    );
    let package = package_policy(&body, &keyring).unwrap();
    let wrong_key = PolicyLoader::with_clock(other, || 1_758_630_000.0);
    let error = wrong_key.load_and_verify(&package).unwrap_err();
    assert!(error.message().contains("signature"), "{}", error.message());

    let loader = PolicyLoader::with_clock(keyring.clone(), || 1_758_630_000.0);
    loader.load_and_verify(&package).unwrap();
    let mut tampered = package;
    if let Json::Object(object) = &mut tampered {
        object.insert("signature".to_string(), Json::string("ab".repeat(32)));
    }
    let error = loader.load_and_verify(&tampered).unwrap_err();
    assert!(error.message().contains("signature"), "{}", error.message());

    let no_gate = build_policy_body(&[Rule::allow("workspace.read")], &fields);
    let package = package_policy(&no_gate, &keyring).unwrap();
    let error = loader.load_and_verify(&package).unwrap_err();
    assert!(
        error.message().contains("approval gate"),
        "{}",
        error.message()
    );

    let mut allow = Rule::allow("workspace.read");
    let mut approval = Rule::require_approval("workspace.read");
    approval.approval_required = true;
    allow.principal = "worker-1".to_string();
    approval.principal = "worker-1".to_string();
    let conflict = build_policy_body(&[allow, approval], &fields);
    let bundle = loader
        .load_and_verify(&package_policy(&conflict, &keyring).unwrap())
        .unwrap();
    let engine = PolicyEngine::new(bundle);
    let request = CanonicalRequest {
        version: "1".to_string(),
        request_id: "req-1".to_string(),
        session_id: "sess-1".to_string(),
        principal: "worker-1".to_string(),
        action: "workspace.read".to_string(),
        resource: Json::object([("path", Json::string("a.txt"))]),
        payload: Json::empty_object(),
        constraints: Json::empty_object(),
        payload_digest: sha256_hex(&Json::empty_object()).unwrap(),
        nonce: String::new(),
        expires_at: 0.0,
    };
    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, DECISION_DENY);
    assert_eq!(decision.reason, "denied_policy_conflict");
}

#[test]
fn worker_cannot_supply_approval_fields_or_a_foreign_principal() {
    let root = workspace();
    let normalizer = RequestNormalizer::new(&root, ["workspace.read"]).unwrap();
    let mut forged = envelope(
        "workspace.read",
        root.join("allowed").join("a.txt").to_str().unwrap(),
    );
    if let Json::Object(object) = &mut forged {
        object.insert("nonce".to_string(), Json::string("chosen-by-model"));
    }
    let error = normalizer.normalize(&forged, "worker-1").unwrap_err();
    assert!(
        error.message().contains("unknown envelope fields"),
        "{}",
        error.message()
    );

    let error = normalizer
        .normalize(
            &envelope(
                "workspace.read",
                root.join("allowed").join("a.txt").to_str().unwrap(),
            ),
            "other-worker",
        )
        .unwrap_err();
    assert!(error.message().contains("principal"), "{}", error.message());

    let mut external = Json::object([
        ("version", Json::string("1")),
        ("request_id", Json::string("req-2")),
        ("session_id", Json::string("sess-1")),
        ("principal", Json::string("worker-1")),
        ("action", Json::string("external.send_mock")),
        (
            "resource",
            Json::object([
                ("service", Json::string("mail")),
                ("recipient", Json::string("alex@example.com")),
            ]),
        ),
        ("payload", Json::object([("body", Json::string("hello"))])),
        (
            "constraints",
            Json::object([("send_once", Json::Bool(true))]),
        ),
    ]);
    let normalizer = RequestNormalizer::new(&root, ["external.send_mock"]).unwrap();
    let error = normalizer.normalize(&external, "worker-1").unwrap_err();
    assert!(error.message().contains("mock-only"), "{}", error.message());

    if let Json::Object(object) = &mut external {
        object.insert(
            "resource".to_string(),
            Json::object([
                ("service", Json::string("mail")),
                ("recipient", Json::string("alex@example.invalid")),
            ]),
        );
    }
    let request = normalizer.normalize(&external, "worker-1").unwrap();
    assert!(request.binding_digest("1.0.0").is_err());
    let bound = bind(&request, "nonce-from-controller", 1_758_630_000.5);
    assert!(bound.binding_digest("1.0.0").is_ok());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn policy_mac_matches_the_python_prototype() {
    let keyring = KeyRing::new(vec![b'p'; 32], vec![b'a'; 32]).unwrap();
    let body = Json::object([
        ("version", Json::string("1.0.0")),
        ("signer", Json::string("operator-prototype")),
        (
            "rules",
            Json::Array(vec![Json::object([
                ("action", Json::string("workspace.read")),
                ("principal", Json::string("*")),
            ])]),
        ),
    ]);
    let bytes = canonical_bytes(&body).unwrap();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        r#"{"rules":[{"action":"workspace.read","principal":"*"}],"signer":"operator-prototype","version":"1.0.0"}"#
    );
    assert_eq!(
        keyring.sign_policy(&bytes),
        "05034f046ae102e284c5333c783972eba20e14221473dce02e080c8d3ba8d76f"
    );
}

#[test]
fn audit_mac_is_not_the_policy_signature() {
    let keyring = KeyRing::new(
        b"policy-secret-32-bytes-of-material",
        b"audit-secret-32-bytes-of-material!",
    )
    .unwrap();
    let body = canonical_bytes(&Json::object([("event", Json::string("deny"))])).unwrap();
    assert_ne!(keyring.sign_policy(&body), keyring.mac_audit(&body));
    assert!(keyring.verify_policy(&body, &keyring.sign_policy(&body)));
    assert!(!keyring.verify_policy(&body, &keyring.mac_audit(&body)));
}
