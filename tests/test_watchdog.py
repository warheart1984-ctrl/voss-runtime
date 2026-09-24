import subprocess
import sys
import time
import unittest

from voss.watchdog import HealthReport, Watchdog


class WatchdogUnitTest(unittest.TestCase):
    def test_health_ok_by_default(self):
        wd = Watchdog()
        self.assertTrue(wd.health().ok)
        self.assertTrue(wd.accepts_work("worker-1"))

    def test_health_source_failure_propagates(self):
        wd = Watchdog()
        wd.attach(health_source=lambda: HealthReport(False, "audit unavailable"))
        self.assertFalse(wd.health().ok)
        self.assertTrue(wd.accepts_work("worker-1"))  # suspended set is separate

    def test_suspend_stops_new_work_without_killing(self):
        wd = Watchdog()
        wd.suspend("worker-1", reason="drift")
        self.assertFalse(wd.accepts_work("worker-1"))
        self.assertTrue(wd.accepts_work("worker-2"))
        wd.resume("worker-1")
        self.assertTrue(wd.accepts_work("worker-1"))

    def test_kill_terminates_process_and_revokes(self):
        wd = Watchdog()
        revoked = []
        wd.attach(revoke_fn=lambda wid: revoked.append(wid) or 7)
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        wd.register_process("worker-1", proc)

        result = wd.kill("worker-1", reason="drill")
        self.assertTrue(result["process_terminated"])
        self.assertFalse(wd.accepts_work("worker-1"))
        self.assertEqual(revoked, ["worker-1"])
        proc.wait(timeout=5)
        self.assertIsNotNone(proc.poll())

    def test_kill_without_registered_process(self):
        wd = Watchdog()
        wd.attach(revoke_fn=lambda wid: 0)
        result = wd.kill("worker-1", reason="drill")
        self.assertFalse(result["process_terminated"])
        self.assertEqual(result["capabilities_revoked"], 0)


if __name__ == "__main__":
    unittest.main()