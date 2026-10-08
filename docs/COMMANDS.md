# Command reference

Examples use the optional `cm` shortcut. Every command is also available as `command-center`.

## Privileges and options

Live firewall/configuration/lifecycle commands require root. System reports and network reports are read-only and work without root when the operating system permits access. Journal access follows journal permissions. `updates status` can run without root.

| Option | Meaning |
| --- | --- |
| `--dry-run` | Show/validate a proposed mutation without writing settings or applying rules. Native validation runs in live mode. |
| `--stage` | Save desired policy only. Apply several edits, then explicitly reload. |
| `--json` | Structured output on supported read commands. Finite logs return an array; followed logs return JSON lines. |
| `--root DIRECTORY` | Offline configuration workspace. Never changes the host firewall, services, APT or network. |
| `--timeout SECONDS` | Live confirmation deadline, 1–3600 seconds; default 120. `--rollback` is a compatibility spelling. |
| `--no-rollback` | Apply without a confirmation timer. Intended for controlled automation or console operation. |
| `--now` | With enable/disable, also start/stop current enforcement. |
| `--interval MS` | CPU sampling interval, 250–10000 ms; default 1000. |

Options may precede or follow the command. Local option values are kept literal, including values that look like global flags.

`--stage` is for rule/default/profile/alias/logging configuration edits. It is not supported for bans, protection commands, lifecycle or read-only commands. Ordinary mutations refuse uncommitted configuration drift until reload. The running SSH monitor continues using applied settings while desired configuration is staged.

Durations are integers with an optional `s`, `m`, `h` or `d` suffix. Plain integers mean seconds. General durations are bounded to 30 days; a protection window is bounded to one day. Permanent is accepted for ban duration only. Negative durations and compound durations are rejected.

## Rules

~~~text
cm allow  [in|out] SERVICE [OPTIONS]
cm deny   [in|out] SERVICE [OPTIONS]
cm reject [in|out] SERVICE [OPTIONS]
cm limit  [in|out] SERVICE [OPTIONS] [--rate N/UNIT] [--burst N]
~~~

Direction defaults to incoming. SERVICE is a built-in/custom alias, `PORT/tcp`, `PORT/udp`, `PORT/both`, a port range such as `8000-8010/tcp`, or `all`.

For allow/deny/reject, all matches every IP protocol. For limit, all means new TCP SYN traffic to every destination port. Limit supports TCP only.

| Rule option | Meaning |
| --- | --- |
| `--from CIDR` | Numeric source address/network; IPv4 and IPv6 are normalized. |
| `--to CIDR` | Numeric destination address/network. |
| `--interface NAME` | Exact incoming/outgoing interface name; no wildcard or shell expansion. |
| `--family 4/6/any` | Restrict IP family; any is the default. |
| `--comment TEXT` | Printable ASCII, at most 159 bytes; safely quoted in native output. |
| `--rate N/second`, `N/minute`, `N/hour` | Token refill rate, 1–100000; default 6/minute for limit. |
| `--burst N` | Bucket capacity, 1–100000; default 5. |

Hostnames are not resolved in firewall rules. Contradictory address families and duplicate options are rejected. A new identical match/action definition updates its rate/burst/comment while retaining the rule number. Omitted comments are preserved; `--comment ""` clears a comment. Address-only rules use `all` plus the relevant filter.

~~~sh
cm allow ssh --from 198.51.100.0/24
cm allow in 80/tcp --interface eth0
cm reject 8000-8010/tcp --from 2001:db8::/32
cm deny all --from 198.51.100.25
cm allow out 443/tcp --to 203.0.113.10
cm limit ssh --rate 4/minute --burst 4
cm limit all --rate 20/second --burst 40
~~~

The outgoing example allows host-originated TCP to destination port 443 on 203.0.113.10. Under a passive outgoing policy it is usually redundant. It becomes an exception after `default out deny`. It does not allow incoming HTTPS or override another table's drop.

Limits are per source address for incoming traffic and per destination address for outgoing traffic. SYN retransmissions can count; this is a token bucket, not an exact count of unique sessions. All matching rate gates run before ordinary rules. A full tracking set drops matching new SYNs. Policy changes/structural policy repairs reset meters; unchanged reloads, metadata edits and ban-only changes preserve them. Expiry covers the full refill horizon, and all declared meter sets share a 262144-entry capacity budget.

~~~text
cm rules [--json]
cm delete NUMBER
cm move NUMBER before NUMBER
cm default in|out allow|deny
~~~

Numbers are stable IDs, displayed as `[NUMBER]`. Order is shown separately. Deleting rule 2 leaves other numbers unchanged. New IDs are not reused. Ordinary rules are first-match in their displayed order; move a more-specific deny before a broad allow when it should win.

Rules apply immediately when CM is active and save for later when stopped. Active policy changes normally require `confirm` before another mutation.

Explicit deny defaults add essential loopback, network-error, IPv6 discovery and DHCP-client exceptions. In ordinary policies, established/related traffic is accepted after user rules. Isolation has stricter connection-state behavior.

## Aliases

~~~text
cm services [--json]
cm service show NAME [--json]
cm service set NAME PORT/tcp|udp|both
cm service delete NAME
~~~

Built-ins: ssh 22/tcp; http 80/tcp; https 443/tcp; quic 443/udp; dns 53/both; ntp 123/udp; smtp 25/tcp; submission 587/tcp; imap 143/tcp; imaps 993/tcp; wireguard 51820/udp; postgresql 5432/tcp; mysql 3306/tcp.

Custom aliases can override built-ins. Deleting an override restores the built-in value. Existing rules keep their resolved numeric ports when an alias changes.

## Lifecycle, status and reload

~~~text
cm init
cm start
cm stop
cm enable [--now]
cm disable [--now]
cm status [--json]
cm doctor [--json]
cm plan [--json]
cm reload
cm export
cm check
~~~

Init creates passive saved configuration if absent. It does not activate CM.

Start activates the saved CM policy for this boot and starts the loader and required protector. A fresh passive start introduces no restriction and needs no confirmation. Start refuses staged/external desired-file edits until explicit reload.

Stop removes only CM enforcement and preserves saved rules/settings/bans. Boot enablement is unchanged. If a change is pending, stop first rolls it back.

Enable/disable change systemd boot startup only. `--now` adds start/stop. Installation does neither.

Status includes numbered desired rules, activation certainty, CM tables/loader consistency, profile/defaults, startup/service states, expected ban membership, pending/recovery deadlines, guard heartbeat/progress/lag and capacity. Doctor uses the same report. A required heartbeat older than ten seconds, saturation, lag beyond the configured failure window or overdue rollback is unhealthy. Guard counters are since daemon start. Offline status explicitly does not inspect the kernel.

Reload validates desired settings and updates affected CM objects atomically if active; it also commits desired settings when stopped. Metadata-only and unchanged reloads preserve meters and do not require confirmation. It never globally flushes the firewall or starts stopped CM.

Plan compares desired and committed defaults, rule IDs/order and guard/ban scope, and reports affected objects and confirmation seconds. JSON includes both configurations. It changes no files. Dry-run begins with the same summary. Missing current-boot activation is unknown, not stopped; ordinary edits fail until explicit start/stop (or pending rollback) reconciles it.

Export emits the native batch for the desired policy as if CM were active. It does not execute it. Export should be inspected as CM-owned source, not applied over another firewall.

Check validates configuration and the generated batch against the live kernel in check mode. Offline check validates configuration only and says so.

## Confirmation and recovery

~~~text
cm confirm
cm rollback
cm recover
cm recover checkpoint
cm config show
cm config validate
cm config restore
~~~

Confirm accepts a pending change before its deadline, after checking activation certainty, managed kernel/configuration drift and ban membership. Verify management access with a new connection first.

Rollback restores the previous configuration/state from the pending record. A transient timer calls it automatically. Recovery records protect crashes during both apply and rollback.

Recover restores an interrupted transaction. Recover checkpoint explicitly restores the committed configuration/state when established files are missing or invalid. Resolve pending/interrupted operations first.

Config restore replaces desired configuration with the committed version. It does not repair live rule drift; reload does that. Config validate checks the schema without native kernel validation.

An unconfirmed change is reverted when the boot loader runs after reboot. The loader then activates the committed policy. It does not approve staged desired-file edits.

## SSH authentication protection

~~~text
cm protect ssh [--failures N] [--window DURATION] [--ban DURATION|permanent]
               [--scope ssh|all] [--port PORT/tcp]
cm protect ssh status [--json]
cm protect ssh disable
cm protect ssh ignore add CIDR
cm protect ssh ignore delete CIDR
~~~

Defaults: 6 failed authentication events, 10-minute window, 1-hour ban, SSH-port scope, ssh alias port (initially 22/tcp). Failure count is 1–100. `-a` means failures and `-d` means ban duration on protect commands.

~~~sh
cm protect ssh -a 4 --window 10m -d 30m --port 2222/tcp
cm protect ssh --scope all --ban permanent
cm protect ssh ignore add 198.51.100.0/24
~~~

Scope all expands the resulting ban to all incoming host protocols; the trigger remains SSH authentication failures. The monitor does not detect HTTP authentication failures or forwarded-container traffic. An alias alone is not evidence of a service's authentication protocol.

Counts use trusted root OpenSSH journal events, including supported sshd/sshd-session password, public-key and keyboard-interactive messages. Several events can occur in one connection. Settings changes reset attempt/cursor tracking; manual bans remain. Saturation declines admissions, preserves existing bans and cursor progress, and reports dropped events without stopping the monitor. Expected native bans are checked and repaired during idle cycles too.

The monitor pauses during pending confirmation, resumes after confirmation/rollback, and uses applied policy while desired policy is staged. It ignores loopback automatically unless that ignore entry is explicitly removed.

## Address bans

~~~text
cm ban IP [--for DURATION|permanent] [--scope all|ssh]
cm unban IP
cm bans [--json]
~~~

Default manual ban: one hour, all incoming host protocols. IP must be a single numeric address, not a CIDR. SSH scope uses the configured protection-port list. A longer existing ban is retained when re-banned; requested scope is updated. Permanent bans have no native timeout.

Unban removes manual and automatic entries plus failure history for that address. Ignore lists affect automatic protection only. Ban records persist while stopped and are enforced on a later start only if unexpired.

## Profiles

~~~text
cm profiles [--json]
cm profile show NAME [--ssh-port PORT/tcp] [--keep-rules] [--json]
cm use NAME [--ssh-port PORT/tcp] [--keep-rules]
~~~

Profile show is a read-only preview of the resulting desired configuration. Use applies/saves the profile.

An explicit TCP management-port override takes precedence over the SSH alias. Passive does not require an SSH alias; implicit SSH ports for other profiles must resolve to TCP.

| Name | Behavior |
| --- | --- |
| passive | Clear ordinary rules, use passive defaults, disable automatic protection. |
| guard-only | Preserve current policy/rules and enable SSH protection. |
| web-server | Deny incoming by default; SSH, HTTP, HTTPS allowed; outgoing allowed; SSH protection enabled. |
| ssh-only | Deny incoming except SSH; outgoing allowed; SSH protection enabled. |
| isolation | Deny incoming except SSH and ordinary outgoing initiation; retain management replies and essential networking; SSH protection enabled. |

Except guard-only, profiles replace ordinary rules by default. `--keep-rules` retains and combines them. Manual bans remain. Applying a profile does not start inactive CM.

Isolation blocks even pre-existing ordinary outbound connections. It retains loopback, essential control traffic and DHCP. Extra user rules can relax the isolation policy. Changing outgoing defaults exits special isolation reply handling.

## Network

~~~text
cm net [--json]
cm net addresses [--json]
cm net interfaces [--json]
cm net routes [--json]
cm net route get ADDRESS [--json]
cm net dns [--json]
cm net listeners [--json]
cm net public-ip [--family 4|6] [--url HTTPS_URL] [--json]
~~~

Net without a subcommand combines interfaces, addresses and routes. Reports concern the current network namespace. Route get requires a numeric single destination.

DNS uses systemd-resolved's known upstream information when available. Otherwise it reports resolv.conf resolver endpoints, which may be a local stub. Domain/interface-specific selection means there is not necessarily one universally active upstream.

Listeners reports listening TCP and bound UDP sockets. It does not claim to identify each socket's owning process.

Public-IP lookup explicitly queries ipify over HTTPS, or your supplied HTTPS endpoint. It enforces certificate verification, response/address validation, a 128-byte buffer, a 5-second connection deadline and a 10-second total deadline. It does not follow redirects or use environment proxies. Lookup failures return an error rather than a guessed address.

## System reports

~~~text
cm info [--json] [--interval MS]
cm cpu [--json] [--interval MS]
cm memory [--json]
cm disk [--json]
cm inode [--json]
cm os [--json]
cm hardware [--json]
cm time [--json]
cm timezone [--json]
~~~

Info combines CPU, memory, local filesystems and basic system identity. CPU samples aggregate and logical-core counters. Disk/inode reports use statvfs on local filesystems; network filesystems are skipped to avoid hanging on an unreachable mount. Disk and inode views share the filesystem records.

Focused reports use compact text/tables by default and preserve their JSON form with `--json`. CPU-only sampling does not collect memory or mount/filesystem data.

OS includes os-release, kernel and uptime. Hardware includes available DMI/CPU/block-device inventory. Time/timezone includes local/UTC time, configured zone and available systemd synchronization information. Missing optional information is represented as null/unavailable.

## Logging

~~~text
cm logging packets off|low|medium|high
cm logging level debug|info|notice|warning|error|critical
cm logs [--since DURATION] [--level SEVERITY] [--lines N] [--follow] [--json]
~~~

Packet mode defaults to off. Low logs blocked/rejected/banned traffic; medium also logs new accepted traffic; high adds nftables packet-header logging flags. Each logging chain is bounded to 5 events/second with a burst of 10. A throttled log never bypasses a drop/reject.

Administration events go to journald under command-center. Logging level controls the default severity cutoff of the logs view (initially info); administration/security events remain recorded.

Journal events include component/action fields and applicable rule/address fields. Operational failures are recorded at error severity; unavailable SSH cursors are warnings. The logs view includes these fields when present.

Logs defaults to the last hour and at most 200 matching records in a finite view. Lines is 1–10000 and applies to finite views. Follow streams matching records from the requested since window and then new events. JSON follow uses one object per line. Kernel records must have a CM prefix; administrative records must have a trusted root UID.

Journald owns retention and rotation. CM does not delete other services' journal data; see the operations guide for an optional system-wide retention policy.

## Debian updates

~~~text
cm updates status
cm updates enable
cm updates disable
cm updates reboot on|off
cm updates schedule HH:MM|default
cm updates check
cm updates run
cm updates logs
~~~

Status reads effective APT configuration in live mode. Enable/disable controls unattended periodic installation using one CM-owned APT fragment. Automatic reboot starts off and is preserved across enable/disable changes.

Schedule installs/removes one timer drop-in for apt-daily-upgrade.timer. A custom schedule has a fixed daily local time, no randomized delay, and persistent missed-run behavior.

Check delegates to unattended-upgrade dry-run. Run delegates to unattended-upgrade. Logs delegates to its system journal records. Existing origins/exclusions/package policy remain controlled by upstream APT fragments. Externally modified CM-owned files are rejected rather than overwritten.

Package execution and logs do not hold the firewall/lifecycle locks. Owned policy/timer changes use a separate updates lock. CM-controlled systemctl/systemd-run/journalctl helpers have a 30-second deadline; package execution retains upstream coordination and cancellation behavior.

Offline mode writes policy/drop-ins into its workspace and refuses actual update execution.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Operational, validation, privilege, or recovery error |
| 2 | Invalid global flags/usage |
| 3 | Status/doctor detected drift, recovery, unknown/inconsistent activation, unhealthy loader/guard, saturation/lag, or overdue rollback |

An invalid local argument may return code 1. Error text goes to stderr. JSON is supported by rules, bans, plan, profiles/profile preview, services/service show, config show, protection status, status/doctor, system/network reports and logs. Updates, export, check, config validate and mutations use text.
