# Validation record: 2.1.0

This record describes checks that actually completed. The implementation and
regressions for every review recommendation are mapped in
[REVIEW_CHANGES.md](REVIEW_CHANGES.md).

## Local execution

| Check | Observed result |
| --- | --- |
| Strict GCC C17 build with conversion/shadow/format warnings as errors | Passed |
| Core boundary, guard saturation and policy compiler tests | Passed |
| 39 offline CLI integration tests | Passed |
| Seven failure-injection scenarios, including write/fsync/rename/ENOSPC and interrupted recovery | Passed |
| Deterministic parser fuzz smoke: nine seeds and 2304 mutations | Passed |
| Mocked native inspection, membership and atomic ban-delta tests | Passed |
| Full-capacity resource/load checks | Passed |
| GCC -fanalyzer build | Passed |
| Address/undefined sanitizers, local leak scanning disabled | Passed |
| Local native namespace/Netlink/systemd checks | Unavailable in this workspace; executed in CI below |

The workspace cannot create network namespaces, operate native routing/nftables
Netlink, or run systemd as init. Its LeakSanitizer cannot inspect process threads.
CI supplies the relevant kernel, service and leak-scanning environments.

Local full-state evidence covered 4096 bans and 4096 tracked sources with 100
timestamps each: 5,058,068 bytes compact, 9,027,111 bytes pretty-printed, and
12,713,511 bytes with the longest accepted timestamp values. The 16 MiB file
bound accommodates those records. One run observed approximately 222 ms for
state serialization/parsing, 47 ms for a saturated 128-event batch, and 99,292 KiB
peak process RSS. Compiling 256 limits declared 262144 total meter entries.

With 10000 simulated foreign table names, owned snapshots made exactly three
queries and collected two owned objects. A full 4096-ban membership check fell
from approximately 292 ms before indexing to 17 ms after indexing on this
workspace. These measurements apply to this environment; the capacity budget
does not establish total kernel memory usage or a universal throughput guarantee.

## GitHub verification

On 2026-10-08, all five jobs passed for source commit
[181eb7b947435d3378e459ae3a1b2f06faaad608](https://github.com/The-Specter-X/command-center/commit/181eb7b947435d3378e459ae3a1b2f06faaad608)
in [workflow run 37735558291](https://github.com/The-Specter-X/command-center/actions/runs/37735558291).

| CI job | Observed result |
| --- | --- |
| Debian 13 | Strict GCC build, core/39 CLI/seven failure tests, parser smoke, bounded-load/query evidence, Debian packages and provenance passed |
| Debian testing | The same build, offline/load checks, package construction and provenance passed |
| Analysis on Ubuntu 24.04 | Clang address/undefined/leak sanitizers, GCC analyzer, strict Clang build/tests and 30-second coverage-guided libFuzzer run passed |
| Native on Ubuntu 24.04 | Real IPv4/IPv6 namespace packet tests and four read-only networking tests passed |
| Systemd on Debian 13 | Actual lifecycle, real OpenSSH failures, full tracking/ban stores, concurrent service reconciliation, rollback and Debian package lifecycle passed |

Native regressions deplete burst buckets and idle beyond the former expiry for
both IP families and input/output directions. They verify that unchanged reloads
and metadata changes preserve depleted meters; ban element updates retain native
table handles; ban-only structural and membership repair preserve policy; missing
current-boot activation refuses implicit changes; and previous-boot activation
permits legitimate inactive startup. Foreign tables remain present. Existing
precedence, scoped/timed/permanent bans, UDP/reject, established connections,
isolation and packet-log verdict regressions also passed.

The systemd fixture verified guard cursor/progress and control responsiveness
with both stores at capacity. It exercised both post-commit enable/disable
orderings, a real masked-unit start failure followed by reload recovery, and a
completed stop cancelling an in-flight service condition. Actual rollback and
SSH ban commits progressed during a blocked package check. Staged/bad desired
configuration did not change the committed protector. Active upgrades restarted
the guard while preserving policy handles; inactive installs stayed inactive.

Missing/corrupt current state caused a degraded loader to retain checkpoint
enforcement. Explicit stop and package removal independently cleaned owned tables,
including a failed loader that never ran ExecStop. Removal resolved pending
rollback before deleting the executable. Purge preserved foreign tables,
unrelated administrator files and edited APT/timer fragments.

## Retained evidence

The workflow retains packages-0 and packages-1, each containing the main and
shortcut .deb, .buildinfo/.changes, release manifest, SHA256SUMS, compiler and
library versions, installed-package inventory, package contents, offline command
results/logs, and load/query measurements. Manifests identify the workflow merge
SHA and source head SHA and record tracked-source changes.

Additional artifacts retain exact command arguments, exit codes, timestamps and
log hashes for parser fuzzing, native/network checks and systemd/package tests.
Fuzzer failures also retain reproducer files. Packages and provenance are unsigned
CI evidence. Public-IP option validation ran; an external public-IP request was
outside CI.

Use the workflow for the exact source being deployed. This record establishes
the linked run's results, not exhaustive coverage of every topology, traffic
load, third-party firewall or OpenSSH build. Forwarding/NAT, arbitrary service-log
filters and fleet management remain outside the host-firewall contract.

The previous 2.0.0 baseline passed all five jobs in
[workflow run 37664125600](https://github.com/The-Specter-X/command-center/actions/runs/37664125600)
on 2026-10-07. The current record covers the additional 2.1.0 regressions.
