#!/usr/bin/env python3
"""Record build provenance and package contents; this does not sign a release."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def capture(*args):
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode:
        sys.stderr.write(result.stderr)
        result.check_returncode()
    return result.stdout.strip()


def git(*args):
    root = Path(__file__).resolve().parents[1]
    return capture("git", "-c", f"safe.directory={root}", "-C", str(root), *args)


output = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts")
output.mkdir(parents=True, exist_ok=True)
packages = []
for package in sorted(output.glob("*.deb")):
    fields = capture("dpkg-deb", "--show", "--showformat=${Package}\t${Version}\t${Architecture}", str(package)).split("\t")
    contents = output / (package.name + ".contents.txt")
    contents.write_text(capture("dpkg-deb", "--contents", str(package)) + "\n")
    packages.append({"file": package.name, "package": fields[0], "version": fields[1],
                     "architecture": fields[2], "contents": contents.name})
inventory = capture("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\n")
(output / "installed-packages.tsv").write_text(inventory + "\n")
modules = ("libnftables", "json-c", "libsystemd", "libnl-route-3.0", "libcurl")
manifest = {"schema": 1, "source_sha": os.environ.get("GITHUB_SHA") or git("rev-parse", "HEAD"),
            "source_head_sha": os.environ.get("SOURCE_HEAD_SHA"),
            "source_tracked_changes": bool(git("diff", "--name-only", "HEAD")),
            "run_id": os.environ.get("GITHUB_RUN_ID"), "kernel": platform.release(),
            "os_release": Path("/etc/os-release").read_text(),
            "compiler": capture("cc", "--version").splitlines()[0],
            "library_versions": {name: capture("pkg-config", "--modversion", name) for name in modules},
            "packages": packages, "installed_package_inventory": "installed-packages.tsv",
            "signing": "unsigned CI evidence; .changes/.buildinfo and SHA256SUMS retained"}
files = [p for p in sorted(output.iterdir()) if p.is_file() and p.name not in ("release-manifest.json", "SHA256SUMS")]
manifest["files"] = [{"name": p.name, "bytes": p.stat().st_size,
                      "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]
(output / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
files.append(output / "release-manifest.json")
(output / "SHA256SUMS").write_text("".join(
    f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in sorted(files)))
print(f"Recorded provenance for {len(packages)} packages and {len(files)} evidence files.")
