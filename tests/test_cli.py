#!/usr/bin/env python3
"""Offline end-to-end tests: never change host firewall, APT or systemd."""
import copy
import fcntl
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())


class CLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="command-center-test-")
        self.root = Path(self.tmp.name)
        self.config = self.root / "etc/command-center/config.json"
        self.state = self.root / "var/lib/command-center"
        self.runtime = self.root / "run/command-center"

    def tearDown(self):
        self.tmp.cleanup()

    def run_cm(self, *args, ok=True, code=None):
        r = subprocess.run([BINARY, "--root", str(self.root), *args],
                           text=True, capture_output=True, timeout=20)
        if code is not None:
            self.assertEqual(r.returncode, code, (args, r.stdout, r.stderr))
        elif ok:
            self.assertEqual(r.returncode, 0, (args, r.stdout, r.stderr))
        else:
            self.assertNotEqual(r.returncode, 0, args)
        return r

    def cfg(self):
        return json.loads(self.config.read_text())

    def status(self, code=0):
        return json.loads(self.run_cm("status", "--json", code=code).stdout)

    def test_passive_start_and_independent_boot_flags(self):
        self.run_cm("enable")
        self.assertFalse(self.status()["active"])
        self.assertEqual(self.status()["boot_startup"], "enabled")
        self.run_cm("start")
        self.assertFalse((self.state / "pending.json").exists())
        self.assertNotIn("enabled", self.cfg())
        self.assertFalse(self.cfg()["input_drop"] or self.cfg()["output_drop"])
        self.assertEqual(self.cfg()["rules"], [])
        self.assertTrue(self.status()["active"])
        self.run_cm("disable")
        self.assertTrue(self.status()["active"])
        self.run_cm("stop")
        self.assertFalse(self.status()["active"])
        self.run_cm("enable", "--now", "--no-rollback")
        self.assertTrue(self.status()["active"])
        self.run_cm("disable", "--now")
        self.assertFalse(self.status()["active"])

    def test_dry_run_creates_no_files(self):
        self.assertIn("Proposed configuration", self.run_cm("allow", "ssh", "--dry-run").stdout)
        self.run_cm("start", "--dry-run")
        self.run_cm("enable", "--now", "--dry-run")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_numbered_rules_deduplication_and_order(self):
        self.run_cm("allow", "ssh")
        original = self.config.read_bytes()
        self.run_cm("allow", "22/tcp")
        self.assertEqual(self.config.read_bytes(), original)
        self.run_cm("allow", "5432/tcp", "--from", "192.0.2.15/24")
        self.assertEqual(self.cfg()["rules"][1]["source"], "192.0.2.0/24")
        self.run_cm("deny", "ssh")
        self.assertEqual([r["id"] for r in json.loads(self.run_cm("rules", "--json").stdout)], [1, 2, 3])
        self.assertIn("[3]", self.run_cm("status").stdout)
        self.run_cm("move", "3", "before", "1")
        self.assertEqual([r["id"] for r in self.cfg()["rules"]], [3, 1, 2])
        self.run_cm("delete", "1")
        self.run_cm("allow", "https")
        self.assertEqual([r["id"] for r in self.cfg()["rules"]], [3, 2, 4])
        self.run_cm("delete", "ssh", ok=False)
        self.run_cm("delete", "1", ok=False)
        self.run_cm("move", "4", "before", "3")
        self.assertEqual([r["id"] for r in self.cfg()["rules"]], [4, 3, 2])
        self.run_cm("move", "4", "before", "2")
        self.assertEqual([r["id"] for r in self.cfg()["rules"]], [3, 4, 2])

    def test_filters_ranges_and_escaped_comments(self):
        self.run_cm("reject", "out", "8000-8010/tcp", "--to", "203.0.113.10",
                    "--interface", "eth0", "--family", "4", "--comment", 'quoted "value" \\ slash')
        r = self.cfg()["rules"][0]
        self.assertTrue(r["outgoing"])
        self.assertEqual((r["port"], r["port_end"]), (8000, 8010))
        text = self.run_cm("export").stdout
        self.assertIn("th dport 8000-8010", text)
        self.assertIn("oifname", text)
        self.assertIn('quoted \\"value\\"', text)
        self.run_cm("deny", "all", "--from", "2001:db8::/32")
        self.assertEqual(self.cfg()["rules"][1]["protocol"], "any")

    def test_connection_limits(self):
        self.run_cm("limit", "2222/tcp", "--rate", "10/second", "--burst", "7")
        self.run_cm("limit", "2222/tcp", "--rate", "12/hour", "--burst", "8")
        r = self.cfg()["rules"][0]
        self.assertEqual((r["rate"], r["period"], r["burst"], r["id"]), (12, 3600, 8, 1))
        self.run_cm("limit", "all", "--rate", "4/minute", "--burst", "4")
        self.run_cm("limit", "out", "443/tcp", "--to", "203.0.113.10")
        for args in [("53/udp",), ("ssh", "-a", "4"), ("ssh", "--rate", "0/minute"),
                     ("ssh", "--rate", "4/day"), ("ssh", "--burst", "0")]:
            self.run_cm("limit", *args, ok=False)
        text = self.run_cm("export").stdout
        self.assertIn("ct state new tcp flags", text)
        self.assertIn("ip daddr limit rate ", text)

    def test_confirm_and_rollback(self):
        self.run_cm("allow", "ssh")
        self.run_cm("start", "--timeout", "120")
        self.assertTrue((self.state / "pending.json").exists())
        self.run_cm("allow", "http", ok=False)
        self.run_cm("rollback")
        self.assertFalse(self.status()["active"])
        self.run_cm("start")
        self.run_cm("confirm")
        self.assertTrue(self.status()["active"])
        self.run_cm("default", "in", "deny")
        self.assertTrue(self.cfg()["input_drop"])
        self.run_cm("rollback")
        self.assertFalse(self.cfg()["input_drop"])
        self.run_cm("stop")
        self.assertFalse(self.status()["active"])
        self.assertEqual(len(self.cfg()["rules"]), 1)

    def test_deadline_and_reboot_reverts_pending_policy(self):
        self.run_cm("allow", "ssh")
        self.run_cm("start")
        pending = self.state / "pending.json"
        d = json.loads(pending.read_text())
        d["deadline"] = 1
        pending.write_text(json.dumps(d))
        self.run_cm("confirm", ok=False)
        (self.runtime / "active.json").unlink()
        self.run_cm("apply")
        self.assertFalse(pending.exists())
        self.assertTrue(self.status()["active"])
        self.assertFalse(self.cfg()["input_drop"])

    def test_reboot_recovers_intent_before_pending_rollback(self):
        self.run_cm("allow", "ssh")
        self.run_cm("start")
        old = json.loads((self.state / "pending.json").read_text())
        (self.state / "transaction.json").write_text(json.dumps(old))
        (self.runtime / "active.json").unlink()
        self.run_cm("apply")
        self.assertFalse((self.state / "pending.json").exists())
        self.assertFalse((self.state / "transaction.json").exists())
        self.assertTrue(self.status()["active"])

    def test_first_systemd_apply_initializes_saved_files(self):
        self.run_cm("apply")
        self.assertTrue(self.config.exists())
        self.assertTrue((self.state / "state.json").exists())
        self.assertTrue(self.status()["active"])
        self.run_cm("allow", "ssh", "--no-rollback")

    def test_stage_and_reload(self):
        self.run_cm("init")
        self.run_cm("start", "--no-rollback")
        committed = (self.state / "committed.json").read_bytes()
        self.run_cm("allow", "http", "--stage")
        self.run_cm("allow", "https", "--stage")
        self.assertEqual((self.state / "committed.json").read_bytes(), committed)
        self.assertTrue(self.status(3)["configuration_drift"])
        self.run_cm("allow", "ssh", ok=False)
        self.run_cm("reload")
        self.run_cm("confirm")
        self.assertFalse(self.status()["configuration_drift"])
        self.assertEqual(len(self.cfg()["rules"]), 2)
        self.run_cm("ban", "192.0.2.1", "--stage", ok=False)

    def test_stop_preserves_staged_configuration(self):
        self.run_cm("init")
        self.run_cm("start", "--no-rollback")
        self.run_cm("allow", "http", "--stage")
        desired = self.config.read_bytes()
        self.run_cm("stop")
        self.assertEqual(self.config.read_bytes(), desired)
        self.assertNotIn("preserve_desired", json.loads((self.state / "committed.json").read_text()))
        self.assertFalse(self.status(3)["active"])
        self.run_cm("reload")
        self.assertFalse(self.status()["active"])
        self.run_cm("start", "--no-rollback")
        self.assertEqual(len(self.cfg()["rules"]), 1)

    def test_profiles_and_read_only_preview(self):
        self.run_cm("init")
        original = self.config.read_bytes()
        d = json.loads(self.run_cm("profile", "show", "isolation", "--ssh-port", "2222/tcp", "--json").stdout)
        self.assertTrue(d["input_drop"] and d["output_drop"] and d["isolation"])
        self.assertEqual(d["rules"][0]["port"], 2222)
        self.assertEqual(self.config.read_bytes(), original)
        self.run_cm("use", "web-server", "--ssh-port", "2222/tcp")
        self.assertEqual([r["port"] for r in self.cfg()["rules"]], [2222, 80, 443])
        self.assertFalse(self.status()["active"])
        self.run_cm("use", "ssh-only", "--ssh-port", "2222/tcp")
        self.assertEqual([r["port"] for r in self.cfg()["rules"]], [2222])
        self.run_cm("use", "passive")
        self.assertFalse(self.cfg()["input_drop"])
        self.assertEqual(self.cfg()["rules"], [])
        self.run_cm("use", "guard-only")
        self.assertTrue(self.cfg()["guard"]["enabled"])
        self.assertFalse(self.cfg()["input_drop"])
        self.run_cm("use", "unknown", ok=False)

    def test_aliases_resolve_at_creation(self):
        self.assertTrue(json.loads(self.run_cm("services", "--json").stdout))
        self.run_cm("service", "set", "ssh", "2222/tcp")
        self.run_cm("allow", "ssh")
        self.run_cm("service", "set", "ssh", "2223/tcp")
        self.assertEqual(self.cfg()["rules"][0]["port"], 2222)
        self.run_cm("allow", "ssh")
        self.assertEqual(self.cfg()["rules"][1]["port"], 2223)
        self.run_cm("service", "delete", "ssh")
        self.run_cm("allow", "ssh")
        self.assertEqual(self.cfg()["rules"][2]["port"], 22)
        self.run_cm("allow", "dns")
        self.assertEqual(self.cfg()["rules"][-1]["protocol"], "both")
        self.run_cm("service", "set", "bad;name", "22/tcp", ok=False)
        self.run_cm("service", "delete", "http", ok=False)
        self.run_cm("service", "set", "all", "22/tcp", ok=False)

    def test_bans_timed_permanent_and_scoped(self):
        self.run_cm("ban", "2001:0DB8::2", "--for", "10m", "--scope", "ssh")
        b = json.loads(self.run_cm("bans", "--json").stdout)
        self.assertEqual(b[0]["address"], "2001:db8::2")
        self.assertFalse(b[0]["all_ports"])
        self.run_cm("ban", "2001:db8::2", "--for", "permanent")
        self.assertEqual(json.loads(self.run_cm("bans", "--json").stdout)[0]["expires"], 2**63 - 1)
        self.assertIn("permanent", self.run_cm("bans").stdout)
        self.run_cm("ban", "192.0.2.1/24", ok=False)
        self.run_cm("unban", "2001:db8::2")
        self.assertEqual(json.loads(self.run_cm("bans", "--json").stdout), [])

    def test_auth_threshold_window_duration_scope(self):
        self.run_cm("protect", "ssh", "-a", "4", "--window", "2m", "-d", "permanent",
                    "--port", "2222/tcp", "--scope", "all")
        g = json.loads(self.run_cm("protect", "ssh", "status", "--json").stdout)
        self.assertEqual((g["threshold"], g["window"], g["duration"]), (4, 120, 0))
        self.assertEqual(g["ports"], [2222])
        self.assertTrue(g["all_ports"] and g["enabled"])
        self.run_cm("protect", "ssh", "ignore", "add", "192.0.2.1/24")
        self.assertIn("192.0.2.0/24", self.cfg()["guard"]["ignore"])
        self.run_cm("protect", "ssh", "disable")
        self.assertFalse(self.cfg()["guard"]["enabled"])
        self.run_cm("protect", "ssh", "--window", "2d", ok=False)
        self.run_cm("protect", "ssh", "--failures", "101", ok=False)
        self.run_cm("guard", "run", ok=False)

    def test_guard_condition_uses_applied_policy_despite_staging(self):
        self.run_cm("use", "guard-only")
        self.run_cm("start", "--no-rollback")
        self.run_cm("guard-check")
        self.run_cm("use", "passive", "--stage")
        self.run_cm("guard-check")
        self.config.write_text("{malformed desired")
        self.run_cm("guard-check")
        self.run_cm("config", "restore")
        self.run_cm("protect", "ssh", "disable", "--no-rollback")
        self.run_cm("guard-check", code=1)

    def test_logging_settings(self):
        self.run_cm("logging", "packets", "high")
        self.run_cm("logging", "level", "critical")
        self.assertEqual((self.cfg()["packet_log"], self.cfg()["log_level"]), (3, 2))
        text = self.run_cm("export").stdout
        self.assertIn("flags all", text)
        self.assertIn("counter drop", text)
        self.run_cm("logging", "packets", "unknown", ok=False)
        self.run_cm("logs", ok=False)

    def test_external_edit_requires_reload(self):
        self.run_cm("allow", "ssh")
        d = self.cfg()
        d["guard"]["threshold"] = 10
        self.config.write_text(json.dumps(d))
        self.run_cm("allow", "http", ok=False)
        self.run_cm("config", "validate")
        self.run_cm("reload")
        self.run_cm("allow", "http")

    def test_recover_partial_write(self):
        self.run_cm("allow", "ssh")
        old = json.loads((self.state / "committed.json").read_text())
        (self.state / "transaction.json").write_text(json.dumps(old))
        self.config.write_text('{"broken": true}')
        self.run_cm("allow", "http", ok=False)
        self.run_cm("recover")
        self.assertEqual(self.cfg(), old["config"])
        self.assertFalse((self.state / "transaction.json").exists())

    def test_recovery_preserves_staged_desired_when_requested(self):
        self.run_cm("init")
        self.run_cm("allow", "http", "--stage")
        desired = self.config.read_bytes()
        old = json.loads((self.state / "committed.json").read_text())
        old["preserve_desired"] = True
        (self.state / "transaction.json").write_text(json.dumps(old))
        self.run_cm("recover")
        self.assertEqual(self.config.read_bytes(), desired)

    def test_boot_uses_committed_config_not_malformed_desired(self):
        self.run_cm("allow", "ssh")
        original = self.config.read_bytes()
        self.config.write_text("{broken")
        self.run_cm("apply")
        self.assertEqual(self.config.read_text(), "{broken")
        self.run_cm("config", "restore")
        self.assertEqual(self.config.read_bytes(), original)

    def test_boot_refuses_missing_checkpoint_in_existing_installation(self):
        self.run_cm("allow", "ssh")
        self.run_cm("default", "in", "deny")
        self.run_cm("start", "--no-rollback")
        original = self.config.read_bytes()
        checkpoint = self.state / "committed.json"
        checkpoint.unlink()
        self.run_cm("apply", ok=False)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse(checkpoint.exists())
        self.assertTrue(json.loads((self.runtime / "active.json").read_text())["active"])

    def test_protector_requires_a_tcp_ssh_alias(self):
        self.run_cm("service", "set", "ssh", "22/udp")
        original = self.config.read_bytes()
        self.run_cm("protect", "ssh", ok=False)
        self.assertEqual(self.config.read_bytes(), original)
        self.run_cm("protect", "ssh", "--port", "2222/tcp")
        self.assertEqual(self.cfg()["guard"]["ports"], [2222])

    def test_guard_condition_waits_for_transient_lock_contention(self):
        self.run_cm("use", "guard-only")
        self.run_cm("start", "--no-rollback")
        with (self.runtime / "lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            child = subprocess.Popen([BINARY, "--root", str(self.root), "guard-check"],
                                     text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    child.wait(timeout=.15)
                fcntl.flock(lock, fcntl.LOCK_UN)
                stdout, stderr = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 0, (stdout, stderr))
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)

    def test_strict_json_and_file_security(self):
        self.run_cm("init")
        valid = self.config.read_text()
        for value in [valid.replace('"schema":2', '"schema":2,"schema":2'),
                      valid.replace('"schema":2', '"schema":2,"\\u0073chema":2'),
                      valid + " {}", '{"schema":2,"input_drop":"false"}', valid + "\0"]:
            self.config.write_text(value)
            self.run_cm("config", "validate", ok=False)
        self.config.write_text(valid)
        self.config.chmod(0o666)
        self.run_cm("config", "validate", ok=False)
        self.config.chmod(0o600)
        original = self.root / "original.json"
        self.config.rename(original)
        self.config.symlink_to(original)
        self.run_cm("allow", "ssh", ok=False)

    def test_missing_files_and_checkpoint_recovery(self):
        self.run_cm("allow", "ssh")
        self.run_cm("ban", "192.0.2.8", "--for", "1h")
        checkpoint = json.loads((self.state / "committed.json").read_text())
        self.config.unlink()
        self.run_cm("allow", "http", ok=False)
        self.run_cm("config", "restore")
        self.assertEqual(self.cfg(), checkpoint["config"])
        (self.state / "state.json").unlink()
        self.run_cm("unban", "192.0.2.8", ok=False)
        self.run_cm("apply", ok=False)
        self.assertFalse((self.state / "state.json").exists())
        self.run_cm("recover", "checkpoint")
        self.assertEqual(json.loads((self.state / "state.json").read_text()), checkpoint["state"])

    def test_lock_blocks_concurrent_writes_and_reads(self):
        self.run_cm("init")
        with (self.runtime / "lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_cm("allow", "ssh", ok=False)
            self.run_cm("status", ok=False)

    def test_invalid_committed_records(self):
        self.run_cm("init")
        record = self.state / "committed.json"
        original = json.loads(record.read_text())
        cases = []
        for key, value in [("schema", 2), ("unknown", True), ("deadline", "tomorrow"),
                           ("active", "false"), ("preserve_desired", 5)]:
            d = copy.deepcopy(original)
            d[key] = value
            cases.append(d)
        d = copy.deepcopy(original)
        d["state"]["cursor"] = 5
        cases.append(d)
        for d in cases:
            record.write_text(json.dumps(d))
            self.run_cm("status", "--json", ok=False)
        record.write_text(json.dumps(original))
        self.assertFalse(self.status()["drift"])

    def test_update_policy_and_external_edit_guard(self):
        self.run_cm("updates", "enable")
        self.run_cm("updates", "reboot", "on")
        self.assertIn("enabled", self.run_cm("updates", "status").stdout)
        self.run_cm("updates", "disable")
        self.run_cm("updates", "schedule", "03:15")
        timer = self.root / "etc/systemd/system/apt-daily-upgrade.timer.d/90-command-center.conf"
        self.assertIn("03:15:00", timer.read_text())
        self.run_cm("updates", "schedule", "25:00", ok=False)
        self.run_cm("updates", "schedule", "default")
        self.assertFalse(timer.exists())
        fragment = self.root / "etc/apt/apt.conf.d/90command-center"
        self.assertEqual(fragment.stat().st_mode & 0o777, 0o644)
        self.assertIn('Automatic-Reboot "true"', fragment.read_text())
        fragment.write_text("// administrator policy\n")
        self.run_cm("updates", "enable", ok=False)
        self.run_cm("updates", "run", ok=False)

    def test_invalid_inputs_do_not_mutate(self):
        self.run_cm("allow", "ssh")
        original = self.config.read_bytes()
        for service in ["0/tcp", "65536/tcp", "22/sctp", "22;flush/tcp", "22/tcp\n",
                        "-1/tcp", "http;whoami", "30-20/tcp"]:
            self.run_cm("allow", service, ok=False)
        for source in ["localhost", "192.0.2.1/33", "::/129", "::1%lo", "192.0.2.1;drop"]:
            self.run_cm("allow", "ssh", "--from", source, ok=False)
        for options in [("--from", "192.0.2.1", "--to", "2001:db8::1"),
                        ("--from", "192.0.2.1", "--family", "6"),
                        ("--comment", "bad\ncomment"),
                        ("--from", "192.0.2.1", "--from", "192.0.2.2")]:
            self.run_cm("allow", "ssh", *options, ok=False)
        self.assertEqual(self.config.read_bytes(), original)

    def test_global_flags_do_not_consume_local_values(self):
        self.run_cm("allow", "ssh", "--comment", "--json")
        self.assertEqual(self.cfg()["rules"][0]["comment"], "--json")
        self.run_cm("allow", "http", "--json", ok=False)

    def test_system_reports_json(self):
        info = json.loads(self.run_cm("info", "--json", "--interval", "250").stdout)
        self.assertTrue(info["cpus"])
        for cpu in info["cpus"]:
            if cpu["available"]:
                self.assertTrue(0 <= cpu["busy_percent"] <= 100)
        self.assertLessEqual(info["memory"]["available_bytes"], info["memory"]["total_bytes"])
        for name in ("cpu", "memory", "disk", "inode", "os", "hardware"):
            self.assertIsInstance(json.loads(self.run_cm(name, "--json", "--interval", "250").stdout), (dict, list))
        self.run_cm("net", "routes", ok=False)

    def test_missing_activation_is_unhealthy_and_never_implicitly_stops(self):
        self.run_cm("allow", "ssh")
        self.run_cm("default", "in", "deny")
        self.run_cm("start", "--no-rollback")
        checkpoint = self.state / "committed.json"
        before = checkpoint.read_bytes()
        (self.runtime / "active.json").unlink()
        status = self.status(code=3)
        self.assertFalse(status["activation_known"])
        self.assertTrue(status["activation_drift"])
        self.run_cm("allow", "http", "--no-rollback", ok=False)
        self.assertEqual(checkpoint.read_bytes(), before)
        self.run_cm("start", "--no-rollback")
        self.assertTrue(self.status()["active"])
        self.run_cm("allow", "http")
        (self.runtime / "active.json").unlink()
        self.run_cm("confirm", ok=False)
        self.assertTrue((self.state / "pending.json").exists())
        self.run_cm("rollback")
        self.assertTrue(self.status()["active"])

    def test_previous_boot_activation_is_inactive(self):
        self.run_cm("start", "--no-rollback")
        checkpoint = self.state / "committed.json"
        saved = json.loads(checkpoint.read_text())
        saved["boot_id"] = "previous-boot"
        checkpoint.write_text(json.dumps(saved))
        (self.runtime / "active.json").unlink()
        self.run_cm("allow", "http")
        self.assertFalse(self.status()["active"])
        self.assertFalse((self.state / "pending.json").exists())

    def test_metadata_plan_and_reload_preserve_policy(self):
        self.run_cm("use", "guard-only")
        self.run_cm("start", "--no-rollback")
        self.run_cm("service", "set", "internal", "8080/tcp", "--stage")
        plan = json.loads(self.run_cm("plan", "--json").stdout)
        self.assertTrue(plan["metadata_changed"])
        self.assertFalse(plan["policy_rebuild"])
        self.assertEqual(plan["confirmation_seconds"], 0)
        self.run_cm("reload")
        self.assertFalse((self.state / "pending.json").exists())
        self.run_cm("logging", "level", "debug")
        self.assertFalse((self.state / "pending.json").exists())
        self.run_cm("allow", "http", "--stage")
        plan = json.loads(self.run_cm("plan", "--json").stdout)
        self.assertTrue(plan["policy_rebuild"])
        self.assertEqual(plan["added_rules"], [1])
        self.assertEqual(plan["confirmation_seconds"], 120)

    def test_profile_override_and_comment_clearing(self):
        self.run_cm("service", "set", "ssh", "22/udp")
        self.run_cm("use", "passive")
        preview = json.loads(self.run_cm("profile", "show", "ssh-only", "--ssh-port",
                                         "2222/tcp", "--json").stdout)
        self.assertEqual(preview["guard"]["ports"], [2222])
        self.run_cm("use", "ssh-only", "--ssh-port", "2222/tcp")
        self.run_cm("allow", "http", "--comment", "old")
        self.run_cm("allow", "http")
        self.assertEqual(self.cfg()["rules"][-1]["comment"], "old")
        self.run_cm("allow", "http", "--comment", "")
        self.assertEqual(self.cfg()["rules"][-1]["comment"], "")
        identity = self.cfg()["rules"][-1]["id"]
        self.run_cm("allow", "http", "--comment", "replacement")
        self.assertEqual(self.cfg()["rules"][-1]["comment"], "replacement")
        self.assertEqual(self.cfg()["rules"][-1]["id"], identity)

    def test_external_timer_edits_are_not_replaced_or_removed(self):
        self.run_cm("updates", "schedule", "03:15")
        timer = self.root / "etc/systemd/system/apt-daily-upgrade.timer.d/90-command-center.conf"
        generated = timer.read_text()
        lines = generated.splitlines(keepends=True)
        reordered = "".join([*lines[:2], lines[3], lines[2], *lines[4:]])
        for original in (generated + "AccuracySec=30s\n", generated.replace("Persistent=true", "Persistent=false"),
                         reordered, generated.replace("# Managed by Command Center.", "# Administrator")):
            with self.subTest(fragment=original):
                timer.write_text(original)
                for value in ("04:00", "default"):
                    self.run_cm("updates", "schedule", value, ok=False)
                    self.assertEqual(timer.read_text(), original)

    def test_overdue_rollback_and_independent_locks(self):
        self.run_cm("start")
        self.run_cm("default", "in", "deny")
        pending = self.state / "pending.json"
        record = json.loads(pending.read_text())
        record["deadline"] = 1
        pending.write_text(json.dumps(record))
        self.assertTrue(self.status(code=3)["rollback_overdue"])
        with (self.runtime / "updates.lock").open("w+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_cm("rollback")
        with (self.runtime / "lifecycle.lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            old = self.config.read_bytes()
            self.run_cm("protect", "ssh", "--no-rollback", ok=False)
            self.assertEqual(self.config.read_bytes(), old)

    def test_bans_preserve_staged_desired_configuration(self):
        self.run_cm("allow", "ssh")
        self.run_cm("allow", "http", "--stage")
        desired = self.config.read_bytes()
        self.run_cm("ban", "192.0.2.44")
        self.assertEqual(self.config.read_bytes(), desired)
        self.run_cm("unban", "192.0.2.44")
        self.assertEqual(self.config.read_bytes(), desired)


if __name__ == "__main__":
    unittest.main(verbosity=2)
