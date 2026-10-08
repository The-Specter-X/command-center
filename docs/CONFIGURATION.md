# Configuration and persistence

## Requirements and supported scope

The implementation targets Linux host firewalls on Debian 13 with systemd. It uses C17, libnftables >= 1.0.9, json-c >= 0.15, libsystemd >= 247, libnl-route >= 3.2 and libcurl >= 7.85.

Debian 12's stock nftables version is below the declared build floor. Debian testing is a compatibility build target, not a promise that every future library change is supported.

Firewall operations need root/CAP_NET_ADMIN in the current namespace. Service control needs a running systemd manager. Observation commands report the current host/namespace, including when an offline configuration root is selected; offline network/journal/time service queries are rejected.

CM does not manage forwarding, NAT, container-published bridge ports, SSH server configuration, package repositories, cloud security groups, or upstream firewalls.

## Files

| Path | Purpose |
| --- | --- |
| /etc/command-center/config.json | Desired configuration, schema 2 |
| /var/lib/command-center/state.json | Ban expiry, authentication attempts and journal cursor, schema 1 |
| /var/lib/command-center/committed.json | Applied configuration/state checkpoint and activation |
| /var/lib/command-center/applied.json | Normalized structural snapshot of CM kernel objects |
| /var/lib/command-center/transaction.json | Previous state for an interrupted atomic operation |
| /var/lib/command-center/pending.json | Previous state and deadline for timed confirmation |
| /run/command-center/active.json | Intended runtime activation for the current boot |
| /run/command-center/lock | Shared-read/exclusive-mutation lock |
| /run/command-center/guard.lock | One lifetime authentication-journal reader |
| /run/command-center/lifecycle.lock | Serializes administrative intent through service reconciliation |
| /run/command-center/updates.lock | Separate lock for owned update/timer configuration |
| /run/command-center/guard-health.json | Guard heartbeat, journal progress/lag and capacity telemetry |
| /etc/apt/apt.conf.d/90command-center | CM-owned unattended-update/reboot fragment |
| /etc/systemd/system/apt-daily-upgrade.timer.d/90-command-center.conf | Optional owned daily schedule |

CM directories are mode 0700 and private JSON files are mode 0600. APT and systemd drop-ins are mode 0644 because upstream tools and unprivileged effective-policy reporting need to read them. They must still be owned by the operating user and not writable by other users.

Offline mode places the same directory layout under the supplied root. Its boot flag is simulated by /etc/command-center/boot.json. It never controls host services or firewall state.

## Default desired configuration

~~~json
{
  "schema": 2,
  "next_id": 1,
  "input_drop": false,
  "output_drop": false,
  "isolation": false,
  "packet_log": 0,
  "log_level": 6,
  "profile": "passive",
  "aliases": [],
  "rules": [],
  "guard": {
    "enabled": false,
    "all_ports": false,
    "threshold": 6,
    "window": 600,
    "duration": 3600,
    "ports": [22],
    "ignore": ["127.0.0.0/8", "::1/128"]
  }
}
~~~

Activation is deliberately absent from desired configuration. Current activation lives under /run; boot startup lives in systemd enablement. This keeps start/stop independent of enable/disable.

Runtime activation and committed checkpoints record the Linux boot ID. A missing marker for an active checkpoint in the same boot is unknown activation, reported as unhealthy; ordinary edits cannot interpret it as a stop request. Use explicit start/stop, or rollback when a change is pending. A checkpoint from a previous boot does not turn CM on when startup is disabled. Legacy records without a boot ID remain readable and acquire one on the next write.

| Field | Values and meaning |
| --- | --- |
| schema | Exactly 2 for desired configuration |
| next_id | Next stable rule ID; greater than every existing ID |
| input_drop/output_drop | Explicit CM default deny switches |
| isolation | Replace general established-flow acceptance with management reply handling |
| packet_log | 0 off, 1 low, 2 medium, 3 high |
| log_level | Journal view cutoff: critical 2 through debug 7 |
| profile | Descriptive selected-profile/custom label |
| aliases | Up to 64 named numeric port/protocol definitions |
| rules | Ordered ordinary rules; IDs remain stable |
| guard.enabled | Automatic SSH protection desired state |
| guard.all_ports | SSH-triggered bans affect all incoming host protocols |
| guard.threshold | 1–100 failed log events |
| guard.window | 1–86400 seconds |
| guard.duration | 1–2592000 seconds; 0 means permanent |
| guard.ports | 1–32 TCP management ports |
| guard.ignore | Up to 64 numeric IPv4/IPv6 CIDRs |

A rule contains id, action, port, port_end, protocol, source, destination, interface, comment, outgoing, family, rate, burst and period. Family is 0/4/6. Period is 1/60/3600 seconds. Rates/bursts are nonzero only for limit. Protocol is tcp/udp/both, or any with an all-port rule.

All fields are required. Generate a valid configuration with `config show` or `profile show` before editing. Schema 1 beta configuration is not silently adopted: this redesign uses a different policy and activation model. Keep a backup and recreate the desired policy explicitly for a fresh schema-2 deployment.

## Validation and bounds

CM rejects unknown JSON keys, duplicate keys (including escaped spellings), wrong types, nonfinite JSON numbers, embedded NULs, trailing data, invalid UTF-8, oversized files, inconsistent IP families, duplicate IDs/definitions, invalid rates and unsafe paths.

Address inputs are numeric. Networks are normalized to their actual prefix, and IPv4-mapped addresses are normalized to IPv4. Interface names and aliases use a bounded identifier grammar. Comments use printable ASCII and are escaped when compiled.

Application files are opened relative to checked directories without following symlinks. Reads require regular singly linked files with the correct owner and safe permissions. Writes use a same-directory temporary file, fsync, atomic rename and directory fsync.

| Resource | Limit |
| --- | --- |
| Ordinary rules | 256 |
| Ignore CIDRs | 64 |
| Aliases | 64 |
| Management ports | 32 |
| Persisted bans | 4096 |
| Tracked authentication sources | 4096 |
| Failure timestamps per source | 100 |
| Dynamic connection-meter entries | Up to 65536 per set; 262144 total declared capacity |
| JSON/text application file | 16 MiB |
| JSON nesting | 32 levels |
| Rule comment | 159 bytes |
| Finite log view | 10000 records |

Manual admission to a full ban store returns an error. The automatic guard declines new admissions, keeps all existing bans/tracking, persists successful work and cursor progress, and reports saturation without exiting. It retains up to the newest 100 timestamps for an existing source. No permanent ban is evicted to make space.

Each limit declares two IP-family sets. Per-set capacity is the smaller of 65536 and floor(262144 / number of declared sets), so 256 limit rules receive 512 entries per set. A full packet-meter set drops matching new SYNs. Meter expiry is max(2 × period, ceil(burst × period / rate)) + 1 seconds; idle state cannot disappear before its bucket could fully refill. The entry budget is a capacity bound, not a measured kernel-memory ceiling or volumetric DDoS protection. The guard's 256 MiB service limit covers its userspace process, not all kernel allocations.

## Desired versus committed policy

Ordinary changes compare desired settings with the committed checkpoint and refuse unapproved edits. `--stage` intentionally writes desired policy without applying it. `config validate` checks the schema; `check` also performs native validation in live mode. `reload` approves and applies desired changes.

A manual or automatic ban reconciliation uses applied policy without overwriting staged desired policy. Its recovery intent preserves the desired file as well.

Boot/startup loads the committed checkpoint. A malformed desired file cannot replace the approved policy during boot. Missing or invalid current ban state uses checkpoint bans at boot, reports the problem and requires explicit checkpoint recovery; it does not silently discard bans.

Counters, native handles, dynamic meter entries and elapsed set timeouts are excluded from structural drift comparison. Modifying a rule, chain policy, hook, set definition or other managed structure is detected. Snapshot work lists table names and the two managed tables; only status inventories foreign base chains.

Ban membership is verified separately, including origin, scope, permanent/timed status and remaining expiry, with a two-second natural-expiry allowance. Status flags missing/extra bans; reload repairs them. A running guard checks and repairs membership on idle cycles as well as event batches. Consistent ban-only updates use atomic element changes; unsupported/failed element operations fall back to rebuilding the CM ban table while preserving policy meters.

Policy, ban scope, guard detection and metadata are classified separately. Alias/display/profile-label changes and unchanged reloads preserve native policy and do not require confirmation. Policy semantics or policy-table structural repair rebuild meters; ban-table structural repair preserves the policy table.

## Reboots and service state

Installing packages leaves current CM activation and boot startup off. `enable` creates the loader's systemd boot enablement; it does not turn filtering on immediately. `stop` removes only CM tables and marks runtime activation off; committed rules remain available for the next enabled boot.

At boot, /run starts fresh. The loader resolves interrupted and unconfirmed operations, loads the committed policy, and reinstates unexpired bans. Timed bans keep their original wall-clock deadline. Permanent bans have no native timeout.

The loader is ordered before network-pre.target and after existing nftables/UFW/netfilter-persistent loaders when those are part of the boot transaction. Docker and other owners retain their own tables. An external service that later globally flushes the ruleset can remove CM tables; status detects this and reload restores CM-owned objects.

The SSH monitor is wanted by the loader, gated by applied protection settings, and tied to loader stop/restart. Enablement is needed only for the base loader; do not independently enable the guard for normal operation.
