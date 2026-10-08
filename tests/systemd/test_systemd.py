#!/usr/bin/env python3
"""Run only in the disposable systemd CI container."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
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
        if (expected in (0, 3) and r.returncode == 1 and "operation is in progress" in r.stderr
                and time.monotonic() < deadline):
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


def unit_active(unit):
    r = subprocess.run(["systemctl", "is-active", unit], text=True, capture_output=True, timeout=10)
    assert r.returncode in (0, 3), (unit, r.returncode, r.stdout, r.stderr)
    return r.returncode == 0 and r.stdout.strip() == "active"


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


def reinstall():
    run("apt-get", "install", "--reinstall", "-y",
        "/command-center_2.1.0_amd64.deb", "/command-center-shortcut_2.1.0_all.deb")


def table_handle(rules):
    return next(x["table"]["handle"] for x in rules["nftables"] if "table" in x)


def fault_barrier(*args, **faults):
    temporary = tempfile.TemporaryDirectory(prefix="cm-systemd-barrier-")
    ready, release = Path(temporary.name) / "ready", Path(temporary.name) / "release"
    env = {**os.environ, **faults, "CM_TEST_READY": str(ready), "CM_TEST_RELEASE": str(release)}
    child = subprocess.Popen(["/src/build/test-faults", "--no-rollback", *args], env=env,
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_for(lambda: ready.exists() or child.poll() is not None, seconds=10)
        assert ready.exists(), child.communicate()
    except BaseException:
        if child.poll() is None:
            child.kill()
        child.communicate()
        temporary.cleanup()
        raise
    return child, release, temporary


def finish_barrier(child, release, temporary):
    release.touch()
    out, err = child.communicate(timeout=10)
    temporary.cleanup()
    assert child.returncode == 0, (out, err)


def replace_state(record):
    state = Path("/var/lib/command-center/state.json")
    with open("/run/command-center/lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        staged = state.with_name("test-state.tmp")
        staged.write_text(json.dumps(record))
        staged.chmod(0o600)
        os.replace(staged, state)


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
# A full tracking table declines new sources while keeping the daemon and cursor alive.
run("systemctl", "stop", "command-center-guard.service")
tracking = json.loads(Path("/var/lib/command-center/state.json").read_text())
stamp = int(time.time())
tracking["attempts"] = [{"address": f"2001:db8::{i+1:x}", "times": [stamp]} for i in range(4096)]
replace_state(tracking)
run("systemctl", "start", "command-center-guard.service")
failures()
wait_for(lambda: json.loads(Path("/run/command-center/guard-health.json").read_text())["dropped"] >= 2)
assert unit_active("command-center-guard.service")
capacity = json.loads(cm("status", "--json", expected=3))
assert capacity["guard_saturated"] and not capacity["guard_health_stale"]
assert not automatic_ban()
run("systemctl", "stop", "command-center-guard.service")
tracking = json.loads(Path("/var/lib/command-center/state.json").read_text())
tracking["attempts"] = []
replace_state(tracking)
run("systemctl", "start", "command-center-guard.service")
failures()
wait_for(automatic_ban)
cm("unban", "127.0.0.1")
# Full ban storage retains every permanent manual entry and reports declined admissions.
run("systemctl", "stop", "command-center-guard.service")
full = json.loads(Path("/var/lib/command-center/state.json").read_text())
full["attempts"] = []
full["bans"] = [{"address": f"10.64.{i//256}.{i%256}", "expires": 2**63-1,
                 "automatic": False, "all_ports": True} for i in range(4096)]
replace_state(full)
run("systemctl", "start", "command-center-guard.service")
failures()
wait_for(lambda: json.loads(Path("/run/command-center/guard-health.json").read_text())["dropped"] >= 1)
assert unit_active("command-center-guard.service")
assert len(json.loads(cm("bans", "--json"))) == 4096
assert json.loads(cm("status", "--json", expected=3))["guard_saturated"]
run("systemctl", "stop", "command-center-guard.service")
full = json.loads(Path("/var/lib/command-center/state.json").read_text())
full["attempts"], full["bans"] = [], []
replace_state(full)
run("systemctl", "start", "command-center-guard.service")
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
# Guard membership is repaired even when no new authentication failure arrives.
failures()
wait_for(automatic_ban)
run("nft", "delete", "element", "inet", "command_center_bans", "auto_ssh4", "{", "127.0.0.1", "}")
wait_for(lambda: "127.0.0.1" in run("nft", "list", "set", "inet", "command_center_bans", "auto_ssh4"))
cm("unban", "127.0.0.1")
# Both post-commit orderings remain serialized through service reconciliation.
for first, second in (("disable", "enable"), ("enable", "disable")):
    cm("protect", "ssh", *(["--port", "2222/tcp"] if first == "disable" else ["disable"]))
    child, release, temporary = fault_barrier("protect", "ssh",
        *(["disable"] if first == "disable" else ["--port", "2222/tcp"]), CM_TEST_HOLD_RECONCILE="1")
    try:
        before_conflict = Path("/etc/command-center/config.json").read_bytes()
        conflict = subprocess.run(["/usr/bin/command-center", "--no-rollback", "protect", "ssh",
                                  *(["disable"] if second == "disable" else ["--port", "2222/tcp"])],
                                  text=True, capture_output=True, timeout=5)
        assert conflict.returncode == 1 and "operation is in progress" in conflict.stderr, conflict
        assert Path("/etc/command-center/config.json").read_bytes() == before_conflict
    finally:
        finish_barrier(child, release, temporary)
    cm("protect", "ssh", *(["disable"] if second == "disable" else ["--port", "2222/tcp"]))
    assert unit_active("command-center-guard.service") == (second == "enable")
cm("protect", "ssh", "--port", "2222/tcp")
# A failed service job leaves a recoverable committed policy, and reload retries it.
run("systemctl", "stop", "command-center-guard.service")
run("systemctl", "mask", "--runtime", "command-center-guard.service")
try:
    failed_job = subprocess.run(["/usr/bin/command-center", "--no-rollback", "protect", "ssh", "--port", "2222/tcp"],
        capture_output=True, text=True, timeout=15)
    assert failed_job.returncode == 1 and "masked" in failed_job.stderr, failed_job
finally:
    run("systemctl", "unmask", "--runtime", "command-center-guard.service")
assert json.loads(cm("status", "--json", expected=3))["guard_applied_enabled"]
cm("reload")
assert unit_active("command-center-guard.service")
# The actual rollback timer and guard can progress during a slow package check.
cm("logging", "packets", "low", "--timeout", "3", guarded=True)
child, release, temporary = fault_barrier("updates", "check", CM_TEST_PACKAGE_BARRIER="1")
try:
    wait_for(lambda: not Path("/var/lib/command-center/pending.json").exists(), seconds=10)
    wait_for(lambda: unit_active("command-center-guard.service"), seconds=5)
    assert json.loads(cm("config", "show"))["packet_log"] == 0
    failures()
    wait_for(automatic_ban, seconds=5)
    assert child.poll() is None
    cm("unban", "127.0.0.1")
finally:
    finish_barrier(child, release, temporary)
# The service condition and daemon use the committed policy during bad desired-file edits.
config = Path("/etc/command-center/config.json")
config.write_text("{bad desired file")
run("systemctl", "restart", "command-center-guard.service")
assert run("systemctl", "is-active", "command-center-guard.service").strip() == "active"
cm("config", "restore")
# Upgrade the active protector without replacing the loader's kernel policy.
guard_pid = run("systemctl", "show", "command-center-guard.service", "--property=MainPID", "--value")
saved_config = config.read_bytes()
before_upgrade = json.loads(run("nft", "--json", "list", "table", "inet", "command_center"))
reinstall()
assert run("systemctl", "is-active", "command-center-guard.service").strip() == "active"
assert int(guard_pid) > 0
new_guard_pid = run("systemctl", "show", "command-center-guard.service", "--property=MainPID", "--value")
assert int(new_guard_pid) > 0 and new_guard_pid != guard_pid
assert config.read_bytes() == saved_config
after_upgrade = json.loads(run("nft", "--json", "list", "table", "inet", "command_center"))
assert table_handle(before_upgrade) == table_handle(after_upgrade), "Upgrade replaced live firewall."
# A timed rollback must restart a protector that the pending policy stopped.
cm("protect", "ssh", "disable", "--timeout", "3", guarded=True)
wait_for(lambda: not Path("/var/lib/command-center/pending.json").exists())
wait_for(lambda: unit_active("command-center-guard.service"))
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
# A loader that failed after applying policy never ran ExecStop; explicit stop still cleans it.
state_file = Path("/var/lib/command-center/state.json")
state_saved = state_file.read_bytes()
state_file.unlink()
run("systemctl", "start", "command-center.service", expected=1)
assert run("systemctl", "is-active", "command-center.service", expected=3).strip() == "failed"
assert json.loads(run("nft", "--json", "list", "table", "inet", "command_center"))
cm("stop")
tables = json.loads(run("nft", "--json", "list", "tables"))["nftables"]
assert not any(x.get("table", {}).get("name") in ("command_center", "command_center_bans") for x in tables)
state_file.write_bytes(state_saved)
state_file.chmod(0o600)
run("systemctl", "reset-failed", "command-center.service")
reinstall()
assert not json.loads(cm("status", "--json"))["active"]
assert run("systemctl", "is-active", "command-center.service", expected=3).strip() == "inactive"
assert run("systemctl", "is-active", "command-center-guard.service", expected=3).strip() == "inactive"
cm("enable", "--now")
assert json.loads(cm("status", "--json"))["active"]
assert json.loads(cm("status", "--json"))["boot_startup"] == "enabled"
run("systemctl", "restart", "command-center.service")
assert json.loads(cm("status", "--json"))["policy_table_present"]
before_upgrade = json.loads(run("nft", "--json", "list", "table", "inet", "command_center"))
reinstall()
assert config.read_bytes() == saved
after_upgrade = json.loads(run("nft", "--json", "list", "table", "inet", "command_center"))
assert table_handle(before_upgrade) == table_handle(after_upgrade), "Package upgrade replaced live firewall."
assert run("systemctl", "is-active", "command-center-guard.service", expected=3).strip() == "inactive"
cm("start")
assert json.loads(cm("status", "--json"))["policy_table_present"]
cm("default", "out", "deny", "--timeout", "120", guarded=True)
assert Path("/var/lib/command-center/pending.json").exists()
unrelated = Path("/etc/command-center/administrator-notes.txt")
unrelated.write_text("keep this file\n")
cm("updates", "schedule", "01:23")
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
assert not Path("/etc/systemd/system/apt-daily-upgrade.timer.d/90-command-center.conf").exists()
assert not Path("/usr/bin/cm").exists()
# Removal also handles a failed loader with live CM tables while preserving another owner.
reinstall()
cm("start")
cm("allow", "2222/tcp")
cm("updates", "enable")
cm("updates", "schedule", "03:15")
timer = Path("/etc/systemd/system/apt-daily-upgrade.timer.d/90-command-center.conf")
timer.write_text(timer.read_text() + "AccuracySec=5min\n")
apt_policy = Path("/etc/apt/apt.conf.d/90command-center")
apt_policy.write_text(apt_policy.read_text() + '// administrator change\n')
cm("stop")
Path("/var/lib/command-center/state.json").write_text("{corrupt state")
run("systemctl", "start", "command-center.service", expected=1)
assert json.loads(run("nft", "--json", "list", "table", "inet", "command_center"))
run("apt-get", "remove", "-y", "command-center", "command-center-shortcut")
tables = json.loads(run("nft", "--json", "list", "tables"))["nftables"]
assert not any(x.get("table", {}).get("name") in ("command_center", "command_center_bans") for x in tables)
assert json.loads(run("nft", "--json", "list", "table", "inet", "administrator"))
run("apt-get", "purge", "-y", "command-center")
assert "AccuracySec=5min" in timer.read_text()
assert "administrator change" in apt_policy.read_text()
print("Packaged lifecycle, boot flags, rollback, confirmation, real SSH failures, expiry, staged protection, "
      "journal, reporting, APT scheduling, restart/reinstall, removal and purge passed.")
