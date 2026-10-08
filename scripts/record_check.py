#!/usr/bin/env python3
"""Retain a check's exact command, result and output without obscuring its exit code."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

output, command = Path(sys.argv[1]), sys.argv[2:]
assert command, "a command is required"
output.parent.mkdir(parents=True, exist_ok=True)
started = datetime.now(timezone.utc).isoformat()
with output.open("w") as log:
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in child.stdout:
        log.write(line)
        sys.stdout.write(line)
    result = child.wait()
record = {"schema": 1, "command": command, "exit_code": result,
          "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
          "source_sha": os.environ.get("GITHUB_SHA"),
          "source_head_sha": os.environ.get("SOURCE_HEAD_SHA"),
          "run_id": os.environ.get("GITHUB_RUN_ID"),
          "log_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}
output.with_suffix(output.suffix + ".json").write_text(json.dumps(record, indent=2) + "\n")
sys.exit(result)
