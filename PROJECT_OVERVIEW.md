# Command Center: tool overview

## Purpose

Command Center combines a predictable host firewall with the routine observations and controls needed on a Debian server. The main program is written in C. It uses supported libraries for nftables, Netlink, systemd, JSON and HTTPS; package-update execution is delegated to Debian's update tools with fixed argument vectors.

The canonical command is `command-center`. A separate package provides `cm` without forcing a command-name conflict on installations that already use Debian config-manager.

## Product decisions

| Decision | Result |
| --- | --- |
| Passive first start | Existing filtering is preserved. Closing incoming or outgoing traffic requires a rule or profile. |
| Explicit table ownership | Only `inet command_center` and `inet command_center_bans` are rebuilt or removed. |
| Host scope | Input/output are managed; forwarding/NAT and bridge-container published ports are not. |
| Persistent configuration | Rules, aliases, profiles, protection settings and ban expiries survive restarts. |
| Separate runtime and boot controls | Stop removes current CM filtering; disable prevents its loader from starting next boot. |
| Numbered rules | Numbers are stable IDs. Deleting a rule does not renumber the others. |
| Visible first-match ordering | `move` changes precedence. Bans and rate gates run before ordinary rules. |
| Explicit reload | Validated desired configuration replaces only CM objects, in one native batch. |
| Applied-policy checkpoint | Reboots load committed policy even if an unapproved desired file is malformed or staged. |
| SSH safety timer | Live policy changes have a confirmation deadline and automatic rollback. |
| Native observations | Network reports use Netlink/procfs; system reports use procfs/sysfs/statvfs/systemd. |
| Journal ownership | Journald handles storage and rotation; CM filters its own events without vacuuming other services' logs. |

## Firewall model

CM uses an nftables `inet` family table so one configuration covers IPv4 and IPv6. The policy table has input/output base chains at priority 0. Its separate ban table has an input base chain at priority -20 so a ban affects existing as well as new incoming flows.

A passive chain with policy accept introduces no restriction and cannot cancel another chain's drop. This is why separate tables provide ownership isolation, while traffic decisions can still interact.

CM's rule actions are:

- **Allow:** accept matching traffic within CM.
- **Deny:** drop matching traffic.
- **Reject:** send a TCP reset or an ICMP/ICMPv6 port-unreachable response.
- **Limit:** apply a per-address token bucket to new TCP SYN packets, then permit the service subject to ordinary ordering and other tables.

Incoming meters use the source address; outgoing meters use the destination address. All matching rate gates run before ordinary allows, including overlapping rules. Tracking sets expire after the full refill horizon and share a 262144-entry total capacity budget. A full tracking set drops matching new SYNs. Policy changes/rebuilds reset meters; unchanged reloads, metadata edits and ban-only reconciliation preserve them.

With explicit deny defaults, CM permits loopback, essential network-error messages, IPv6 neighbor/router discovery, and DHCP client exchanges. These are foundational network exceptions, not open application ports.

In normal restrictive policies, established/related traffic can continue after user rules have been considered. Explicit deny/reject rules can therefore block a previously established matching flow. Isolation removes general established-flow exceptions and permits replies to incoming management TCP sessions only.

## Profiles

| Profile | Incoming | Outgoing | Protection |
| --- | --- | --- | --- |
| `passive` | Preserve behavior; empty allow policy | Preserve behavior | Disabled |
| `guard-only` | Preserve the current policy/rules | Preserve the current policy/rules | SSH protection enabled |
| `web-server` | Deny default; allow management SSH, HTTP, HTTPS | Allow default | SSH protection enabled |
| `ssh-only` | Deny default; allow management SSH | Allow default | SSH protection enabled |
| `isolation` | Deny default; allow management SSH | Deny default; management replies and essential networking exceptions | SSH protection enabled |

Except for guard-only, applying a profile replaces the ordinary rule list unless `--keep-rules` is requested. Manual bans remain. Profile names describe behavior; there is no ambiguous easy/medium/hard scale.

Isolation blocks ordinary outgoing DNS, NTP, web/API access, updates, and pre-existing outbound TCP flows. It retains loopback, essential control traffic, DHCP, and replies to SSH arriving on the specified management port. Additional explicit user rules can relax it.

## Authentication protection and bans

Packet rate limiting cannot identify a wrong password. The SSH protector instead reads trusted OpenSSH journal records, counts failures per source address within a configured window, and creates native ban-set elements once the threshold is reached.

Three settings are independent:

1. Failure threshold, initially 6.
2. Counting window, initially 10 minutes.
3. Ban duration, initially 1 hour; permanent is also supported.

The counted events are failed password, public-key and keyboard-interactive authentication records in the supported OpenSSH formats. Multiple failures can occur in one connection. A scope of `all` still uses SSH failures as its trigger, then bans all incoming host protocols from that address. It is not a detector for HTTP login failures or every service on the server.

Loopback networks are ignored automatically by default. Administrators can add trusted management networks. Manual bans remain explicit and are not suppressed by the automatic-protection ignore list.

The monitor has one lifetime reader lock. It persists its cursor and attempt state, detects unavailable journal cursors, and avoids replaying obsolete entries. During a pending live change it pauses until confirmation or rollback. Staged desired configuration does not stop the monitor or replace its applied policy.

At capacity, it declines new admissions and advances the journal cursor while preserving existing bans and successful work. Status includes heartbeat, lag, saturation, expected ban membership and rollback deadlines. A readable `plan` shows policy impact before reload; manual and automatic bans use committed settings while desired edits are staged.

Timed bans keep an absolute expiry across restarts, while native set timeouts expire them even if the daemon stops. Permanent bans have no native timeout. Stop removes enforcement but keeps ban records; a later start reinstates unexpired bans.

## Lifecycle and recovery

| Command | Current kernel | Next boot |
| --- | --- | --- |
| `start` | Apply committed/validated CM settings and start its loader/needed monitor | Unchanged |
| `stop` | Remove CM tables and stop its monitor | Unchanged |
| `enable` | Unchanged | Enable loader |
| `disable` | Unchanged | Disable loader |
| `enable --now` | Start | Enable loader |
| `disable --now` | Stop | Disable loader |
| `reload` | Rebuild CM tables from desired settings if active | Save committed settings |
| `--stage` mutation | Unchanged | Remains uncommitted until reload |

CLI start refuses uncommitted desired-file edits; reload approves them explicitly. At boot the service loads the committed checkpoint. Installation leaves both boot startup and current activation off.

Native nftables check mode runs before application. A durable intent record stores the previous configuration/state before kernel mutation. If persistence or application fails, CM attempts restoration; if restoration cannot finish, the recovery record remains.

A timed confirmation record exists before a protected live change is applied. The timer can restore policy after the caller disconnects. A reboot resolves unconfirmed changes before loading the committed policy. Saved policy, runtime activation and systemd unit state are reported separately.

## Observation and maintenance

Network commands live under `cm net`:

- **addresses:** local IPv4/IPv6 addresses and interface scope.
- **interfaces:** names, MTU, state, MAC, byte and error counters.
- **routes / route get:** routing tables and a kernel lookup for a numeric destination.
- **dns:** systemd-resolved upstream information when available; otherwise resolv.conf endpoints with the distinction explained.
- **listeners:** listening TCP sockets and bound UDP sockets in the current namespace.
- **public-ip:** an explicitly requested, certificate-verified HTTPS lookup with a size bound and deadline.

System commands provide per-core sampled CPU usage, memory/swap, local filesystem capacity/inodes, OS/kernel/uptime, available hardware inventory, and local/UTC time and timezone. Missing optional hardware or synchronization fields are reported as unavailable rather than invented.

Logs use the system journal. Packet verbosity is off/low/medium/high; packet logging is rate-limited independently of the packet verdict. Administration events remain recorded, while `logging level` selects the default `logs` view severity.

Update controls manage one owned APT fragment and one owned timer drop-in. Existing administrator files and package-origin policy remain with APT/unattended-upgrades. CM provides policy, check/run/logs, reboot control and daily scheduling without implementing a package manager.

## Delivery and assurance

The repository contains the implementation, a man page, Debian packages, hardened systemd units, detailed documentation, unit/boundary tests, offline command tests, real IPv4/IPv6 namespace tests, read-only networking tests, and a disposable systemd/OpenSSH package-lifecycle test.

CI performs strict GCC/Clang builds, address/undefined/leak sanitizers, GCC static analysis, Debian 13/testing package builds, kernel packet tests and actual journal/SSH tests. [Validation](docs/VALIDATION.md) records observed results and limits.

Enterprise deployment also requires independent security review, target-image validation, operational ownership and a supported release process. This repository does not claim a completed external audit, container-forwarding policy, volumetric DDoS protection, a general Fail2ban filter engine, fleet management or remote administration.
