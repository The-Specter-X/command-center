#!/usr/bin/env python3
"""Deterministic failures use a test-only executable and private offline roots."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
FAULTS = str(Path(sys.argv.pop(1)).resolve())


class Failures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cm-failures-")
        self.root = Path(self.tmp.name)
        self.state = self.root / "var/lib/command-center"
        self.config = self.root / "etc/command-center/config.json"
        self.runtime = self.root / "run/command-center"

    def tearDown(self):
        self.tmp.cleanup()

    def cm(self, *args, faults=None, code=0):
        result = subprocess.run([FAULTS if faults else BINARY, "--root", str(self.root), *args],
                                env={**os.environ, **(faults or {})}, text=True,
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, code, (args, result.stdout, result.stderr))
        return result

    def baseline(self):
        self.cm("allow", "ssh")
        self.cm("start", "--no-rollback")
        return self.config.read_bytes(), (self.state / "committed.json").read_bytes()

    def restored(self, baseline):
        self.assertEqual(self.config.read_bytes(), baseline[0])
        self.assertEqual((self.state / "committed.json").read_bytes(), baseline[1])
        self.assertFalse((self.state / "transaction.json").exists())
        self.assertFalse((self.state / "pending.json").exists())
        self.cm("status", "--json")

    def test_write_failures_restore_committed_generation(self):
        before = self.baseline()
        for name in ("transaction.json", "config.json", "state.json", "active.json", "committed.json"):
            with self.subTest(file=name):
                self.cm("allow", "http", "--no-rollback", faults={"CM_TEST_FAIL_WRITE": name}, code=1)
                self.restored(before)

    def test_rename_and_file_fsync_failures(self):
        before = self.baseline()
        for operation in ("CM_TEST_FAIL_RENAME", "CM_TEST_FAIL_FSYNC"):
            for name in ("transaction.json", "config.json", "state.json", "active.json", "committed.json"):
                with self.subTest(operation=operation, file=name):
                    value = f".{name}." if operation.endswith("FSYNC") else name
                    self.cm("allow", "http", "--no-rollback", faults={operation: value}, code=1)
                    self.restored(before)

    def test_directory_fsync_after_config_rename_and_disk_full(self):
        before = self.baseline()
        for full in (False, True):
            with self.subTest(disk_full=full):
                fault = {"CM_TEST_FAIL_FSYNC": "/etc/command-center"}
                if full:
                    fault["CM_TEST_DISK_FULL"] = "1"
                self.cm("allow", "http", "--no-rollback", faults=fault, code=1)
                self.restored(before)

    def barrier_process(self, *args, **faults):
        ready, release = self.root / "ready", self.root / "release"
        env = {**os.environ, **faults, "CM_TEST_READY": str(ready), "CM_TEST_RELEASE": str(release)}
        child = subprocess.Popen([FAULTS, "--root", str(self.root), *args], env=env,
                                 text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        until = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < until and child.poll() is None:
            time.sleep(.01)
        if not ready.exists():
            child.kill()
            self.fail(child.communicate())
        return child, release

    def test_interrupted_commit_and_rollback_recover(self):
        before = self.baseline()
        for command in (("allow", "http", "--no-rollback"), ("rollback",)):
            with self.subTest(command=command):
                if command[0] == "rollback":
                    self.cm("allow", "http")
                for path in (self.root / "ready", self.root / "release"):
                    path.unlink(missing_ok=True)
                child, _ = self.barrier_process(*command, CM_TEST_HOLD_WRITE="committed.json")
                try:
                    self.assertTrue((self.state / "transaction.json").exists())
                    child.kill()
                    child.communicate(timeout=5)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate()
                self.cm("recover")
                if (self.state / "pending.json").exists():
                    self.cm("rollback")
                self.restored(before)

    def test_interrupted_first_apply_recovers_complete_passive_installation(self):
        child, _ = self.barrier_process("apply", CM_TEST_HOLD_WRITE="active.json")
        child.kill()
        child.communicate(timeout=5)
        self.cm("recover")
        self.assertTrue(self.config.exists())
        self.assertTrue((self.state / "state.json").exists())
        status = json.loads(self.cm("status", "--json").stdout)
        self.assertFalse(status["active"])
        self.assertFalse((self.state / "transaction.json").exists())

    def test_slow_package_check_does_not_block_expired_rollback(self):
        before = self.baseline()
        self.cm("allow", "http")
        pending = self.state / "pending.json"
        record = json.loads(pending.read_text())
        record["deadline"] = 1
        pending.write_text(json.dumps(record))
        child, release = self.barrier_process("updates", "check", CM_TEST_PACKAGE_BARRIER="1")
        try:
            self.cm("status", "--json", code=3)
            self.cm("rollback")
            self.cm("ban", "192.0.2.8", "--for", "10m", "--no-rollback")
            self.assertEqual(json.loads(self.cm("bans", "--json").stdout)[0]["address"], "192.0.2.8")
            self.assertEqual(self.config.read_bytes(), before[0])
            self.assertFalse(pending.exists())
            self.assertIsNone(child.poll())
        finally:
            release.touch()
            out, err = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, (out, err))

    def test_cpu_is_independent_of_mountinfo(self):
        fault = {"CM_TEST_FAIL_FOPEN": "/proc/self/mountinfo"}
        cpu = self.cm("cpu", "--json", "--interval", "250", faults=fault)
        self.assertTrue(json.loads(cpu.stdout))
        disk = self.cm("disk", "--json", faults=fault, code=1)
        self.assertIn("mountinfo", disk.stderr)


if __name__ == "__main__":
    unittest.main()
