#!/usr/bin/env python3
"""Seed the pure fuzzer with valid CLI exports; all file writes stay in a temp root."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

binary, corpus = Path(sys.argv[1]).resolve(), Path(sys.argv[2])
corpus.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="cm-fuzz-seed-") as root:
    def cm(*args):
        subprocess.run([str(binary), "--root", root, *args], check=True, capture_output=True)
    cm("allow", "ssh", "--comment", 'quoted "comment"')
    cm("limit", "https", "--rate", "7/hour", "--burst", "10")
    cm("ban", "2001:db8::a", "--for", "10m", "--scope", "ssh")
    config = (Path(root) / "etc/command-center/config.json").read_bytes()
    state = (Path(root) / "var/lib/command-center/state.json").read_bytes()
    bundle = (Path(root) / "var/lib/command-center/committed.json").read_bytes()
    seeds = {"config": config, "state": state, "bundle": bundle,
             "duplicate": b'{"x":1,"\\u0078":2}', "ipv4": b"192.0.2.3/24",
             "ipv6": b"2001:db8::3/64", "port": b"2222/tcp", "duration": b"30d",
             "ssh": b"Failed password for invalid user x from 192.0.2.1 port 40000 ssh2"}
    tracking = json.loads(state)
    tracking["attempts"] = [{"address": "192.0.2.8", "times": [1000, 1001, 1002]}]
    seeds["attempts"] = json.dumps(tracking).encode()
    for name, data in seeds.items():
        (corpus / name).write_bytes(data)
