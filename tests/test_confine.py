"""The worker job blocks child processes. It does not change the user token."""
from __future__ import annotations

import subprocess
import sys
import unittest

from voss.confine import confine_pid, release_job


class ConfineTest(unittest.TestCase):
    def test_confined_process_cannot_create_a_child(self) -> None:
        script = (
            "import subprocess,sys\n"
            "sys.stdin.readline()\n"
            "try:\n"
            "    subprocess.check_call([sys.executable, '-c', 'raise SystemExit(0)'])\n"
            "except Exception:\n"
            "    print('blocked', flush=True)\n"
            "else:\n"
            "    print('spawned', flush=True)\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        job = confine_pid(proc.pid)
        try:
            assert proc.stdin is not None and proc.stdout is not None
            proc.stdin.write("\n")
            proc.stdin.flush()
            line = proc.stdout.readline().strip()
        finally:
            release_job(job)
            proc.wait(timeout=5)
        self.assertEqual(line, "blocked")


if __name__ == "__main__":
    unittest.main()
