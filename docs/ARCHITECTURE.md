# Architecture and security boundaries

## Components

| Module | Responsibility |
| --- | --- |
| main.c | CLI dispatch, privileges, lifecycle and service coordination |
| commands.c | Rule construction/order, aliases, profiles and protection settings |
| config.c | Strict desired/state schemas, address normalization and bounds |
| common.c | Checked file IO, locking, parsing and fixed-argument subprocess execution |
| firewall.c | Native nftables compilation, check/apply, snapshots and drift |
| transaction.c | Durable intents, checkpoints, confirmation, rollback and boot replay |
| guard.c | Trusted OpenSSH journal parsing, per-source failures and native bans |
| system.c | systemd D-Bus lifecycle and filtered journal display |
| network.c | Netlink interface/address/route reports, resolver/listener reports and HTTPS lookup |
| info.c | Procfs/sysfs/statvfs and time/OS/hardware reporting |
| updates.c | Owned APT policy and timer drop-in; upstream update execution |
| status.c | Desired/applied health, service state and numbered rule report |
| plan.c | Semantic change classification and readable desired/applied plan |

The main implementation is C. It never invokes a shell for user commands or network inspection. Subprocess boundaries are used for systemd transient rollback timers and Debian's package-update tools, with fixed executable paths, validated arguments, an explicit environment, checked statuses, and bounded captured output.

## nftables ownership and interaction

CM reserves two inet-family names: command_center and command_center_bans. Policy rebuilds delete/recreate only affected owned objects in a native atomic batch. Consistent ban-only updates use atomic element deltas, with a ban-table rebuild fallback. Metadata-only changes and unchanged reloads preserve policy meters. Native snapshots inspect owned tables; foreign-chain inventory is kept in status.

There is no built-in set of three nftables tables that CM should share. Tables are named ownership containers; hooks/chain priorities determine packet evaluation. Sharing another owner's table would couple rule order, cleanup and upgrade behavior to that owner.

The policy table has host input/output base chains at priority 0. The ban table has input priority -20 and no output/forwarding chain. CM never owns NAT or forwarding.

An accept in one base chain does not prevent a later base chain from dropping the packet. A drop is terminal. Separate table names prevent destructive edits but cannot guarantee that another firewall owner permits the same traffic.

UFW's chain ownership and Docker's published-port forwarding model are documented in the primary references. CM preserves those owners rather than rewriting their chains or promising that a host-input rule covers Docker's forwarding path.

## Evaluation

Within CM, evaluation is:

1. Incoming ban sets in the earlier ban table.
2. Essential network exceptions, when an explicit deny default is selected.
3. All matching TCP connection-meter gates.
4. Ordinary user rules in displayed first-match order.
5. Ordinary established/related handling, or isolation management-reply handling.
6. Explicit default deny or the passive accept policy.

A meter helper returns only when the per-address under-limit bucket succeeds. Exhausted buckets and a failed/full set reach an unconditional drop. The helper returns to its caller so later overlapping meters and ordinary deny rules still run.

Logging helpers make log generation conditional and bounded, then apply an unconditional verdict. Exceeding a log quota never skips enforcement.

Isolation omits general established/related acceptance. Reply-direction TCP from a configured management source port is accepted; ordinary locally originated sessions remain blocked unless an explicit rule permits them. Loopback, essential ICMP/ICMPv6 and DHCP exceptions are documented parts of the policy.

## Mutations and durable recovery

Mutations hold an exclusive nonblocking application lock. Reads hold a shared lock when an established lock file exists. Contention is an explicit error; readers do not observe a partial multi-file transaction.

Administrative commands hold a separate lifecycle lock through the post-commit systemd job. The global lock is released before service conditions need it; reconciliation re-reads the latest committed intent. Loader/guard unit helpers do not take the lifecycle lock. Package execution and log display hold neither firewall nor lifecycle locks. Owned APT/timer edits use an independent updates lock. CM-controlled systemctl/systemd-run/journalctl helpers have a 30-second deadline; package processes retain upstream cancellation/locking behavior.

For a normal mutation:

1. Read/strictly validate desired settings, current state and committed checkpoint.
2. Refuse pending recovery/confirmation and unexpected desired/kernel drift.
3. Generate and natively validate the candidate batch.
4. Write a confirmation record and arm a systemd timer if the live change is protected.
5. Write a durable prior-state transaction record.
6. Commit one atomic nftables batch.
7. Persist desired/current state, runtime activation, structural snapshot and committed checkpoint.
8. Remove the intent record and synchronize the required protector service.

Persistence failure triggers best-effort restoration from the durable record. Unresolved intent remains recoverable. Rollback itself creates an intent before restoration.

Guard ban commits use the applied configuration and preserve desired-file edits. A preservation flag in their recovery intent prevents a crash recovery from discarding staged configuration.

Boot replay is idempotent: its source is the committed checkpoint. Runtime/checkpoint boot IDs distinguish previous-boot inactivity from a missing marker in the current boot. Unconfirmed changes are rolled back before boot replay. Loader apply also writes durable intent before native changes and persistence.

If the checkpoint is missing while existing configuration, state, kernel snapshots or activation markers remain, boot refuses passive initialization. A protector ExecCondition briefly waits for lock contention; an operational error exits 255 so systemd can retry instead of treating the protector as disabled.

The kernel/files/systemd manager cannot share one physical transaction. A service-control failure after a successful policy commit is reported as an error, and status exposes the applied policy and failed/missing service. Recovery/rollback and service retry remain explicit operational tools.

If startup installs checkpoint policy but current state is invalid, the loader reports degraded state while leaving protective policy loaded. systemd does not execute ExecStop for a failed start. Explicit stop and package removal therefore perform independent CM cleanup, verify owned table absence and preserve recovery evidence on failure. Removal aborts if this cannot be completed while the executable is installed.

## Authentication input boundary

Only trusted root OpenSSH journal matches are counted. Journal matching combines trusted UID and ssh/sshd units with known sshd/sshd-session identifiers. The parser checks the complete supported failed-authentication format and a numeric source address/port. It selects the final source delimiter so a crafted username cannot substitute an earlier apparent address.

The guard persists a journal cursor and bounded timestamps. It counts recent failures, skips obsolete/future records, detects unavailable cursors, ignores configured networks, and avoids double-counting already banned sources. A single lifetime reader prevents duplicate consumers.

Saturation is a nonfatal admission result. Successful decisions and cursor progress are persisted even when another event is declined; no permanent ban is evicted. Runtime health records heartbeat, last progress/event, lag, backlog, pause, capacity and processed/dropped counters since the daemon started. Status checks record validity/freshness (ten seconds), lag versus the configured window, expected bans, activation/table/loader consistency and the pending deadline.

The detector is specifically an OpenSSH detector. Different service log formats require a separately designed/tested source; an arbitrary regex or untrusted application message is not accepted as a ban instruction.

## Privilege and service hardening

The executable refuses setuid use. Normal live mutation requires root. Its services retain CAP_NET_ADMIN only, with no-new-privileges, read-only system protection, private temporary directories, address-family restrictions, and explicit writable application directories.

The monitor's system journal access remains with the host journal; it does not hide the journal in a private namespace. Its unit is capped at 256 MiB. Read-only observation commands do not acquire mutation privileges.

Root is a trusted boundary: root can change CM files, units, kernel rules or any other firewall. CM detects structural drift but does not promise protection against a hostile administrator or compromised kernel.

## External APIs and data

Network inventory uses libnl route APIs and bounded procfs socket records. DNS information uses resolved D-Bus or a labeled resolv.conf fallback. The public-IP endpoint is contacted only by an explicit command; libcurl verifies TLS, rejects non-HTTPS schemes, limits response size/time, disables redirects/proxies, and validates the returned address/family.

System metrics are read from kernel files and statvfs. Optional hardware/time synchronization values can be absent. Native AF values and counters are reported without inventing a generalized cross-platform API.

Update operations retain APT's locks, origins, package policy and unattended-upgrades behavior. CM requires the complete generated APT/timer form to match before replacing/removing it; a retained ownership header alone is insufficient. Purge preserves edited fragments. APT/timer rollback restores a previous owned fragment if reloading the upstream service fails.

## Limits of assurance

The tests cover parser boundaries, file attacks, concurrency, recovery, real packets, service behavior and package lifecycle. They do not establish an external security audit, certified availability, universal OpenSSH log compatibility, fleet-scale behavior, protection against upstream/cloud policy, forwarding/container isolation, or resistance to traffic that exhausts the server before reaching CM.

See the validation record and operations guide before promoting a build to a supported deployment.
