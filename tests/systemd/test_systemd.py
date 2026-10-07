#!/usr/bin/env python3
"""Run only in the disposable systemd CI container."""
import json
from pathlib import Path
import subprocess
import time

assert Path("/.dockerenv").exists()
assert Path("/usr/bin/cm").resolve() == Path("/usr/bin/command-center")


def run(*args, expected=0):
    r = subprocess.run(args, text=True, capture_output=True, timeout=45)
    assert r.returncode == expected, (args, r.returncode, r.stdout, r.stderr)
    return r.stdout


def cm(*args, expected=0, guarded=False):
    deadline = time.monotonic() + 8
    while True:
        argv = ["/usr/bin/command-center", *([] if guarded else ["--no-rollback"]), *args]
        r = subprocess.run(argv, text=True, capture_output=True, timeout=45)
        if r.returncode == 1 and "operation is in progress" in r.stderr and time.monotonic() < deadline:
            time.sleep(.05)
            continue
        assert r.returncode == expected, (args, r.returncode, r.stdout, r.stderr)
        return r.stdout


def wait_for(predicate, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.2)
    raise AssertionError("Condition did not become true")


def failures():
    for _ in range(2):
        r = subprocess.run(["sshpass", "-p", "incorrect-test-password", "ssh", "-p", "2222",
                            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                            "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                            "-o", "NumberOfPasswordPrompts=1", "cmtest@127.0.0.1", "true"],
                           text=True, capture_output=True, timeout=15)
        assert r.returncode in (5, 255) and "Permission denied" in r.stderr, r


def automatic_ban():
    return any(b["automatic"] and b["address"] == "127.0.0.1"
               for b in json.loads(cm("bans", "--json")))


wait_for(lambda: Path("/run/systemd/private").exists(), seconds=30)
run("systemctl", "start", "ssh.service")
assert run("systemctl", "is-enabled", "command-center.service", expected=1).strip() == "disabled"
cm("start")
health = json.loads(cm("status", "--json"))
assert health["active"] and health["policy_table_present"]
assert health["boot_startup"] == "disabled"
cfg = json.loads(cm("config", "show"))
assert not cfg["input_drop"] and not cfg["output_drop"] and not cfg["rules"]
cm("enable")
assert json.loads(cm("status", "--json"))["boot_startup"] == "enabled"
cm("disable")
assert json.loads(cm("status", "--json"))["active"]
cm("allow", "2222/tcp")
cm("default", "in", "deny", "--timeout", "3", guarded=True)
assert Path("/var/lib/command-center/pending.json").exists()
wait_for(lambda: not Path("/var/lib/command-center/pending.json").exists())
assert not json.loads(cm("config", "show"))["input_drop"]
cm("default", "in", "deny", "--timeout", "30", guarded=True)
cm("confirm")
assert json.loads(cm("config", "show"))["input_drop"]
cm("protect", "ssh", "--failures", "2", "--window", "1m", "--ban", "3s", "--port", "2222/tcp")
cm("protect", "ssh", "ignore", "delete", "127.0.0.0/8")
assert run("systemctl", "is-active", "command-center-guard.service").strip() == "active"
cm("guard", "run", expected=1)
failures()
wait_for(automatic_ban)
time.sleep(3.2)
assert not automatic_ban()
# Staging must not stop monitoring or be overwritten when an automatic ban is committed.
cm("protect", "ssh", "--ban", "30s")
cm("allow", "http", "--stage")
desired = Path("/etc/command-center/config.json").read_bytes()
failures()
wait_for(automatic_ban)
assert Path("/etc/command-center/config.json").read_bytes() == desired
assert json.loads(cm("status", "--json", expected=3))["configuration_drift"]
cm("reload")
cm("unban", "127.0.0.1")
# The service condition and daemon use the committed policy during bad desired-file edits.
config = Path("/etc/command-center/config.json")
config.write_text("{bad desired file")
run("systemctl", "restart", "command-center-guard.service")
assert run("systemctl", "is-active", "command-center-guard.service").strip() == "active"
cm("config", "restore")
# A timed rollback must restart a protector that the pending policy stopped.
cm("protect", "ssh", "disable", "--timeout", "3", guarded=True)
wait_for(lambda: not Path("/var/lib/command-center/pending.json").exists())
wait_for(lambda: run("systemctl", "is-active", "command-center-guard.service").strip() == "active")
cm("protect", "ssh", "disable")
assert run("systemctl", "is-active", "command-center-guard.service", expected=3).strip() == "inactive"
logs = json.loads(cm("logs", "--json", "--lines", "50"))
assert any("transaction committed" in r["message"] for r in logs)
assert any(r.get("component") == "ssh" and r.get("address") == "127.0.0.1" for r in logs)
cm("delete", "4294967294", expected=1)
errors = json.loads(cm("logs", "--level", "error", "--json"))
assert any(r.get("action") == "delete" and r["priority"] == 3 for r in errors)
for name in ("time", "timezone", "os", "hardware"):
    assert isinstance(json.loads(cm(name, "--json")), dict)
assert json.loads(cm("net", "route", "get", "127.0.0.1", "--json"))
cm("updates", "enable")
cm("updates", "reboot", "off")
assert "CM_ENABLED='1'" in run("runuser", "-u", "cmtest", "--", "/usr/bin/command-center", "updates", "status")
cm("updates", "schedule", "03:15")
assert "03:15:00" in run("systemctl", "cat", "apt-daily-upgrade.timer")
assert "03:15:00" in run("systemctl", "show", "apt-daily-upgrade.timer", "--property=TimersCalendar", "--value")
assert run("systemctl", "is-active", "apt-daily-upgrade.timer").strip() == "active"
cm("updates", "schedule", "default")
cm("updates", "disable")
run("nft", "add", "table", "inet", "administrator")
saved = config.read_bytes()
cm("stop")
assert not json.loads(cm("status", "--json"))["active"]
assert json.loads(run("nft", "--json", "list", "table", "inet", "administrator"))
cm("enable", "--now")
assert json.loads(cm("status", "--json"))["active"]
assert json.loads(cm("status", "--json"))["boot_startup"] == "enabled"
run("systemctl", "restart", "command-center.service")
assert json.loads(cm("status", "--json"))["policy_table_present"]
before_upgrade = json.loads(run("nft", "--json", "list", "table", "inet", "command_center"))
run("apt-get", "install", "--reinstall", "-y",
    "/command-center_2.0.0_amd64.deb", "/command-center-shortcut_2.0.0_all.deb")
assert config.read_bytes() == saved
after_upgrade = json.loads(run("nft", "--json", "list", "table", "inet", "command_center"))
table_handle = lambda rules: next(x["table"]["handle"] for x in rules["nftables"] if "table" in x)
assert table_handle(before_upgrade) == table_handle(after_upgrade), "Package upgrade replaced live firewall."
# --no-start packaging never starts a previously inactive service.
cm("start")
assert json.loads(cm("status", "--json"))["policy_table_present"]
cm("default", "out", "deny", "--timeout", "120", guarded=True)
assert Path("/var/lib/command-center/pending.json").exists()
unrelated = Path("/etc/command-center/administrator-notes.txt")
unrelated.write_text("keep this file\n")
run("apt-get", "remove", "-y", "command-center", "command-center-shortcut")
assert not Path("/var/lib/command-center/pending.json").exists()
assert not json.loads(Path("/var/lib/command-center/committed.json").read_text())["active"]
remaining_tables = json.loads(run("nft", "--json", "list", "tables"))["nftables"]
assert not any(x.get("table", {}).get("name") in ("command_center", "command_center_bans")
               for x in remaining_tables)
assert json.loads(run("nft", "--json", "list", "table", "inet", "administrator"))
run("apt-get", "purge", "-y", "command-center")
assert unrelated.read_text() == "keep this file\n"
assert not config.exists()
assert not Path("/var/lib/command-center/committed.json").exists()
assert not Path("/etc/apt/apt.conf.d/90command-center").exists()
assert not Path("/usr/bin/cm").exists()
print("Packaged lifecycle, boot flags, rollback, confirmation, real SSH failures, expiry, staged protection, "
      "journal, reporting, APT scheduling, restart/reinstall, removal and purge passed.")
