# Review implementation: 2.1.0

This change implements the findings and bounded improvements from the review of
5771afdd6258c3e405ebb62fe2a918850e2ffdc7. Desired configuration remains schema 2;
existing records without a boot ID remain readable. Native C, two owned inet
tables, Debian/systemd lifecycle and the existing host-firewall scope remain.

| Finding | Result | Regression evidence |
| --- | --- | --- |
| R1: fatal guard saturation/replay | Nonfatal bounded admission, preserved bans/successful work/cursor; indexed membership checks, control-lock admission windows and capacity/drop telemetry | Core full-store/100-timestamp tests; real SSH with both stores full |
| R2: updates hold firewall lock | Package/log execution has no firewall/lifecycle lock; owned update edits use updates.lock; controlled helpers have deadlines | Offline barrier plus actual timed rollback/SSH commits during a slow package check |
| R3: missing activation becomes stop | Current-boot unknown activation refuses edits/confirmation; boot identity distinguishes stopped startup | Offline/native missing-marker and previous-boot cases |
| R4: premature meter expiry | Full-refill horizon plus margin; total declared entry budget | Arithmetic/budget bounds; burst depletion/idle raw SYN counts for IPv4/IPv6 input/output |
| R5: failed-start cleanup gap | Durable loader intent; explicit stop/removal independently cleans and verifies owned table absence | Interrupted first apply; missing/corrupt-state failed loader followed by stop/removal |
| R6: stale service intent | Lifecycle serialization through re-read/reconciliation and service jobs; completed stops tolerate a cancelled service condition | Both deterministic post-commit enable/disable orderings; actual masked-unit failure/retry; cancellation of an in-flight condition |
| R7: metadata resets meters | Semantic policy/guard/ban/metadata classes and separate table drift | Depleted meter and native handle preservation; ban-structure-only repair |
| R8: edited timer overwritten | Complete generated form required before replacement/removal; purge preserves edited fragments | Appended, modified, reordered and unmarked offline cases; package purge |
| R9: CPU collects filesystems | CPU-only collector isolated; shared human report rendering | mountinfo denied: CPU succeeds, disk fails |
| R10: override resolved too late | Explicit TCP override first; passive independent of SSH alias; shared resolution helper | UDP alias plus explicit override/passive cases |
| R11: empty comment ignored | Option presence distinguishes omission from clearing | Preserve/clear/replace while retaining rule ID |

| Addition or simplification | Implementation |
| --- | --- |
| Health invariants | Activation/table/loader/guard checks; heartbeat/progress/lag, saturation and pending deadlines; exit 3 when unhealthy |
| Ban membership | Origin/scope/TTL/permanent checks with natural-expiry tolerance; idle guard repair and explicit reload |
| Plan/diff | `plan [--json]` and dry-run summaries for defaults, rule IDs/order, affected objects and confirmation interval |
| Failure injection | Test-only wrappers for write/fsync/rename/ENOSPC, interrupted commits/rollback/apply and controlled service/package barriers |
| Fuzzing | Pure parser/state/bundle/compiler target under Clang libFuzzer/ASan/UBSan; deterministic smoke in normal checks |
| Resource/load evidence | Full 4096-ban/source stores, 100 timestamps/source, 128-event saturation batch, 256 limits, 10000 simulated foreign tables; JSON measurements |
| Human reports | Focused system/network reports render text/tables; existing JSON retained |
| Release evidence | Source SHA, exact command/results/logs, dependency/package inventories, contents, checksums, buildinfo/changes and unsigned provenance |
| Targeted inspection | Hot path queries table names and owned objects; foreign base-chain inventory remains in status |
| Atomic ban deltas | Consistent state-only updates change elements, with full owned ban-table fallback; policy remains intact |
| Removed redundant work | No package/log firewall lock, metadata rebuild, CPU filesystem collection, duplicate SSH resolution or stale post-commit service decision |

The 262144-entry meter budget bounds declared native capacities, not total kernel
memory. Load/fuzz measurements apply to the recorded environment and do not
establish exhaustive coverage. A hostile root administrator, forwarding/NAT,
container firewall ownership, arbitrary service-log regexes, fleet management,
web daemons and process killing remain outside the project contract.

See [TESTING.md](TESTING.md) for commands, [VALIDATION.md](VALIDATION.md) for checks
that have actually completed, and [OPERATIONS.md](OPERATIONS.md) for recovery.
