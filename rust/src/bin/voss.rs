//! Trusted operator console.
//!
//! The console owns the approval gesture and the kill switch. The worker
//! only proposes. `--auto` approves every gate so the demo can run without
//! a person at the keyboard.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Child;

use voss::canonical::{Json, canonical_bytes, new_id};
use voss::keys::KeyRing;
use voss::policy::package_policy;
use voss::runtime::{default_dev_policy, VossRuntime};

const DEMO: &[(&str, &str, &str)] = &[
    ("read-forwarded-file", "propose:read", "A0 observe, policy grant, logged"),
    ("write-draft", "propose:write", "A1 workspace edit, human approval required"),
    ("send-project-update", "propose:email", "A2 external effect, one-time human approval"),
    ("uncertain-send", "propose:uncertain", "A2 ambiguous outcome -> UNKNOWN, no retry"),
    ("malicious-delete", "propose:delete", "unknown tools -> default deny"),
    ("path-escape", "propose:escape", "traversal -> default deny"),
    ("identity-forge", "propose:admin", "principal forgery -> identity deny"),
];

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let auto = args.iter().any(|arg| arg == "--auto");
    let root = args.iter().position(|arg| arg == "--root").and_then(|index| args.get(index + 1));
    let base = match root {
        Some(path) => PathBuf::from(path),
        None => env::temp_dir().join(format!("voss-demo-{}", new_id(""))),
    };
    if let Err(error) = fs::create_dir_all(&base) {
        eprintln!("cannot create runtime root: {error}");
        std::process::exit(1);
    }
    let workspace = base.join("workspace");
    let outbox = base.join("outbox");
    let audit_path = base.join("audit.jsonl");
    let keyring = match KeyRing::load_or_create(&base) {
        Ok(keyring) => keyring,
        Err(error) => {
            eprintln!("cannot load keys: {error}");
            std::process::exit(1);
        }
    };
    let package = match default_dev_policy(&workspace).and_then(|body| package_policy(&body, &keyring)) {
        Ok(package) => package,
        Err(error) => {
            eprintln!("cannot build policy: {}", error.message());
            std::process::exit(1);
        }
    };
    let runtime = match VossRuntime::open(&workspace, &outbox, &audit_path, keyring, Some(package)) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cannot open runtime: {}", error.message());
            std::process::exit(1);
        }
    };
    let _ = fs::write(
        workspace.join("notes.txt"),
        "Meeting notes: review the draft on Monday.\n",
    );
    println!("Runtime root : {}", base.display());
    println!("Worker       : {}", runtime.worker_principal);
    println!("Policy       : v{} (audit_required, human-gated actions present)", runtime.policy_version);
    println!("Tools        : {}", runtime.tool_names().join(", "));

    let mut worker = match runtime.spawn_worker() {
        Ok(worker) => worker,
        Err(error) => {
            eprintln!("cannot spawn worker: {}", error.message());
            runtime.close();
            std::process::exit(1);
        }
    };
    println!("Worker proc  : pid {} (spawned with clean env)", worker.id());

    let mut killed = false;
    for (name, prompt, note) in DEMO {
        println!("\n--- step: {name} ({note}) ---");
        let envelopes = match runtime.worker_propose(prompt) {
            Ok(Json::Array(envelopes)) => envelopes,
            Ok(_) => {
                println!("worker response was not a list");
                break;
            }
            Err(error) => {
                println!("worker error: {}", error.message());
                break;
            }
        };
        let mut stop = false;
        for envelope in envelopes {
            let text = match canonical_bytes(&envelope) {
                Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
                Err(error) => {
                    println!("proposal encode failed: {}", error.message());
                    continue;
                }
            };
            let response = runtime.handle_envelope(&text);
            let action = envelope.get("action").and_then(Json::as_str).unwrap_or("?");
            println!(
                "proposal: {action} -> {} ({})",
                field(&response, "decision"),
                field(&response, "reason_code")
            );
            if field(&response, "decision") == "REQUIRE_APPROVAL" {
                let flow_id = field(&response, "approval_request_id").to_string();
                if let Ok(description) = runtime.approval_view_text(&flow_id) {
                    println!("\n=== APPROVAL REQUESTED (trusted console) ===");
                    println!("{description}");
                }
                let decision = ask(auto);
                if decision == "KILL" {
                    println!("{}", json_line(&runtime.kill_worker("operator kill", true)));
                    let _ = worker.kill();
                    let _ = worker.wait();
                    println!("KILLED. Further steps will be denied.");
                    killed = true;
                    stop = true;
                    break;
                }
                let result = runtime.resolve_approval(&flow_id, decision, "operator@console");
                println!(
                    "resolution: {} ({}) result={}",
                    field(&result, "decision"),
                    field(&result, "reason_code"),
                    json_line(result.get("result").unwrap_or(&Json::Null))
                );
            } else if field(&response, "decision") == "DENY" {
                println!("  denied: {}", field(&response, "reason_code"));
            }
        }
        if stop {
            break;
        }
    }

    if !killed {
        runtime.revoke_all("console-exit");
        stop_worker(&mut worker);
    }
    println!("\n=== AUDIT SUMMARY ===");
    println!("{}", json_line(&runtime.audit_summary()));
    println!("=== HEALTH ===");
    println!("{}", json_line(&runtime.health_report()));
    println!("=== DRIFT ===");
    println!("{}", json_line(&runtime.drift_report()));
    println!("=== OUTBOX (simulated external effects) ===");
    if let Ok(entries) = fs::read_dir(&outbox) {
        let mut names: Vec<_> = entries.filter_map(|entry| entry.ok()).map(|entry| entry.file_name()).collect();
        names.sort();
        for name in names {
            println!("  {}", name.to_string_lossy());
        }
    }
    runtime.close();
}

fn ask(auto: bool) -> &'static str {
    if auto {
        println!("[auto] APPROVE");
        return "APPROVE";
    }
    println!("Choices: [1] Approve once  [2] Deny  [3] Cancel  [k] KILL worker");
    let stdin = io::stdin();
    loop {
        print!("> ");
        let _ = io::stdout().flush();
        let mut choice = String::new();
        if stdin.read_line(&mut choice).is_err() {
            return "CANCEL";
        }
        match choice.trim().to_ascii_lowercase().as_str() {
            "1" | "approve" => return "APPROVE",
            "2" | "deny" => return "DENY",
            "3" | "cancel" => return "CANCEL",
            "k" | "kill" => return "KILL",
            _ => {}
        }
    }
}

fn stop_worker(worker: &mut Child) {
    if worker.try_wait().ok().flatten().is_none() {
        let _ = worker.kill();
        let _ = worker.wait();
    }
}

fn field<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).unwrap_or("")
}

fn json_line(value: &Json) -> String {
    canonical_bytes(value)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| "null".to_string())
}
