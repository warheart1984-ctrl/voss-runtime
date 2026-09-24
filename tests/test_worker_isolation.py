import json
import os
import subprocess
import sys
import tempfile
import unittest

import voss.chan as chan
from tests._support import make_runtime, outbox_files
from voss.canonical import new_id
from voss.runtime import _clean_env

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class WorkerIsolationTest(unittest.TestCase):
    """Evidence for the worker boundary (Voss RFC 7.1, 8)."""

    def test_clean_env_strips_secret_like_vars(self):
        parent = {
            "PATH": "C:\\bin",
            "VOSS_POLICY_SECRET": "topsecret",
            "AWS_CREDENTIALS": "x",
            "DATABASE_PASSWORD": "y",
            "SAFE_VAR": "ok",
        }
        cleaned = _clean_env(parent)
        for name in ("VOSS_POLICY_SECRET", "AWS_CREDENTIALS", "DATABASE_PASSWORD"):
            self.assertNotIn(name, cleaned, name)
        self.assertIn("PATH", cleaned)
        self.assertIn("SAFE_VAR", cleaned)

    def test_spawned_worker_sees_no_secret_like_env_names(self):
        tmp = tempfile.mkdtemp(prefix="voss-wenv-")
        rt = make_runtime(tmp)
        env = dict(os.environ)
        env.update({"VOSS_POLICY_SECRET": "decoy", "MY_CRED": "decoy"})
        env = _clean_env(env)
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [sys.executable, "-m", "voss.worker", "--selfcheck"],
            capture_output=True, text=True, encoding="utf-8", env=env, cwd=PKG_ROOT,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["found_secret_like_env_names"], [])
        rt.close()

    def test_worker_has_no_tool_module_imports(self):
        src = open(os.path.join(PKG_ROOT, "voss", "worker.py"), encoding="utf-8").read()
        for banned in (
            "from .broker", "from .policy", "from .keys", "from .audit",
            "from .tools", "import socket", "import subprocess",
            "import requests", "from .runtime", "from .watchdog",
            "from .approval", "from .cli",
        ):
            self.assertNotIn(banned, src, banned)

    def test_worker_standalone_produces_only_proposals(self):
        # No broker attached -> no effects can exist, regardless of directives.
        # The worker only talks over an authenticated channel and, with no
        # runtime behind it other than this test driving pipes, can only emit
        # signed proposal payloads.
        tmp = tempfile.mkdtemp(prefix="voss-standalone-")
        outbox = os.path.join(tmp, "outbox")
        os.makedirs(outbox, exist_ok=True)
        workspace = os.path.join(tmp, "workspace")
        os.makedirs(workspace, exist_ok=True)

        key = os.urandom(32)
        sid = new_id("chan-")
        bootstrap_path = os.path.join(tmp, "bootstrap.json")
        with open(bootstrap_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(chan.chan_bootstrap(key, sid)))

        env = dict(os.environ)
        env["VOSS_WORKSPACE"] = workspace
        env["VOSS_CHANNEL_BOOTSTRAP"] = bootstrap_path
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.Popen(
            [sys.executable, "-m", "voss.worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", env=env, cwd=PKG_ROOT, bufsize=1,
        )
        host = chan.ChannelSession(key, sid, "host")

        hello_line = proc.stdout.readline()
        hello_type, hello = host.receive(hello_line)
        self.assertEqual(hello_type, "hello")
        self.assertTrue(hello.get("ready"))
        proc.stdin.write(host.send("hello_ok", {"ok": True}) + "\n")
        proc.stdin.flush()
        # The one-time credential is consumed by the adapter immediately.
        self.assertFalse(os.path.exists(bootstrap_path))

        prompts = [
            "propose:read", "propose:write", "propose:email",
            "propose:delete", "propose:escape", "propose:admin",
        ]
        seen = []
        for i, prompt in enumerate(prompts):
            proc.stdin.write(
                host.send("prompt", {
                    "prompt": prompt, "session_id": f"s{i}",
                    "principal": f"worker-{i}"}) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            resp_type, msg = host.receive(line)
            self.assertEqual(resp_type, "proposal")
            for item in msg["envelopes"]:
                seen.append(item["action"])
                self.assertIn(item["action"], (
                    "workspace.read", "workspace.write", "external.send_mock",
                    "workspace.delete", "shell.exec"))
        self.assertEqual(len(seen), 8)  # read, write, email, delete*2, escape*2, admin
        self.assertIn("workspace.delete", seen)  # model wanted it; no broker exists

        proc.stdin.close()
        proc.wait(timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr.read())
        # The outbox the broker would write to is completely untouched.
        self.assertEqual(outbox_files(outbox), [])

    def test_worker_refuses_to_run_without_bootstrap(self):
        # A worker with no provisioned channel credential refuses to start:
        # there is no unauthenticated fallback mode.
        proc = subprocess.run(
            [sys.executable, "-m", "voss.worker"],
            input="", capture_output=True, text=True, encoding="utf-8",
            env={k: v for k, v in os.environ.items()
                 if k != "VOSS_CHANNEL_BOOTSTRAP"},
            cwd=PKG_ROOT, timeout=30,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("bootstrap", proc.stderr)

    def test_network_primitives_absent_from_trusted_execution_path(self):
        # No socket/http/urllib/shell anywhere in the enforcement core.
        core_files = [
            "canonical.py", "protocol.py", "keys.py", "policy.py",
            "approval.py", "audit.py", "tools.py", "broker.py",
        ]
        banned = ("import socket", "import requests", "import http",
                  "import urllib", "os.system", "import ftplib", "import pty")
        for name in core_files:
            src = open(os.path.join(PKG_ROOT, "voss", name), encoding="utf-8").read()
            for token in banned:
                self.assertNotIn(token, src, f"{name}: {token}")
        # The trusted host launches the worker subprocess; it may use
        # subprocess but must not open sockets or an interactive shell.
        runtime_src = open(os.path.join(PKG_ROOT, "voss", "runtime.py"), encoding="utf-8").read()
        for token in ("import socket", "import requests", "import http", "import urllib", "os.system"):
            self.assertNotIn(token, runtime_src, f"runtime.py: {token}")
        # The worker adapter itself must not possess any process/network control.
        worker_src = open(os.path.join(PKG_ROOT, "voss", "worker.py"), encoding="utf-8").read()
        for token in ("subprocess", "socket", "requests", "os.system"):
            self.assertNotIn(token, worker_src, f"worker.py: {token}")


class WorkerResponseSecrecyTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="voss-secret-")
        self.rt = make_runtime(self._tmp)
        with open(os.path.join(self.rt.workspace_root, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("secret payload that must never leave as plaintext in audit")

    def tearDown(self):
        self.rt.close()

    def test_worker_response_contains_no_secrets_or_payload_plaintext(self):
        env = {
            "version": "1",
            "request_id": "req-123",
            "session_id": self.rt.worker_session,
            "principal": self.rt.worker_principal,
            "action": "external.send_mock",
            "resource": {"service": "mail", "recipient": "alex@example.invalid"},
            "payload": {"subject": "TOP SECRET SUBJECT", "body": "TOP SECRET BODY"},
            "constraints": {"send_once": True},
        }
        resp = self.rt.handle_envelope(json.dumps(env, sort_keys=True))
        self.assertEqual(resp.get("decision"), "REQUIRE_APPROVAL")
        out = self.rt.resolve_approval(resp["approval_request_id"], "APPROVE", "test-human")
        self.assertEqual(out.get("decision"), "ALLOW")

        serialized = json.dumps(out)
        for secret in ("TOP SECRET SUBJECT", "TOP SECRET BODY", "alex@example.invalid"):
            self.assertNotIn(secret, serialized)
        self.assertNotIn(self.rt.keyring._policy_key.hex(), serialized)
        self.assertNotIn(self.rt.keyring._audit_key.hex(), serialized)

        audit_text = open(self.rt.audit.path, encoding="utf-8").read()
        for secret in ("TOP SECRET SUBJECT", "TOP SECRET BODY", "alex@example.invalid"):
            self.assertNotIn(secret, audit_text)


if __name__ == "__main__":
    unittest.main()