# Command Center

A native C administration tool for Debian servers. `command-center` is the canonical executable; the optional `cm` shortcut provides the commands below.

CM manages the host firewall through libnftables, monitors OpenSSH authentication failures through the system journal, reports system and network information, and controls Debian unattended updates.

## The default contract

Installing the package does not start or enable CM. A fresh `cm start` preserves current filtering behavior: no default deny, no implicit SSH exception, and no removal of existing restrictions. Rules and profiles change behavior only when you request them.

CM owns exactly two nftables tables:

- `inet command_center`: host input/output policy and connection meters.
- `inet command_center_bans`: timed and permanent incoming address bans.

It never runs `flush ruleset` and never modifies another application's tables. Reload applies the affected CM objects atomically. Unchanged policy and metadata edits preserve connection meters. Other firewall tables, including Docker's tables, remain effective. A CM allow cannot override a drop in another base chain.

Forwarding and NAT remain under their existing owners. Docker-published bridge ports traverse forwarding/NAT and are outside CM's host input/output policy.

## Features

| Area | Commands and behavior |
| --- | --- |
| Firewall | `allow`, `deny`, `reject`, `limit`; incoming/outgoing; IPv4/IPv6; ports/ranges; source/destination CIDRs; interfaces; comments |
| Rules | Stable numbers, `rules`, `delete NUMBER`, `move NUMBER before NUMBER` |
| Services | SSH, HTTP, HTTPS, DNS and other built-in aliases; custom aliases |
| Lifecycle | `start/stop` for the current boot; `enable/disable` for boot startup; optional `--now` |
| Profiles | `passive`, `guard-only`, `web-server`, `ssh-only`, `isolation` |
| SSH protection | Failed-authentication threshold, counting window, ban duration, ignore networks, SSH/all-port scope |
| Bans | IPv4/IPv6 addresses; timed/permanent; persisted; `bans` and `unban` |
| Recovery | Native batch validation, timed confirmation, rollback, durable crash recovery, drift detection |
| Staging | `--dry-run`, `--stage`, explicit `reload`; boot loads the committed policy |
| System | CPU/core usage, memory/swap, disk/inodes, OS, hardware, time and timezone |
| Network | Addresses, interfaces/counters, routes/route lookup, DNS endpoints, listeners, explicit public-IP lookup |
| Logs | Journald-backed administration and packet events; severity filtering, finite views, follow/JSON |
| Updates | Debian unattended-upgrades policy, automatic-reboot setting and daily schedule |

## Build and install

Target platform: Debian 13 with systemd. CI also builds Debian testing and checks native behavior on Ubuntu 24.04. Required library versions are listed in [Configuration](docs/CONFIGURATION.md).

~~~sh
sudo apt-get update
sudo apt-get install build-essential pkg-config libnftables-dev libjson-c-dev \
  libsystemd-dev libnl-route-3-dev libcurl4-openssl-dev python3 debhelper
make -j2 all check
dpkg-buildpackage -us -uc -b
sudo apt-get install ../command-center_2.1.0_$(dpkg --print-architecture).deb \
  ../command-center-shortcut_2.1.0_all.deb
~~~

The shortcut package is optional and conflicts with Debian's `config-manager` package, which also owns `cm`. Install the main package alone to use `command-center`.

A source installation is also available:

~~~sh
sudo make install
sudo systemctl daemon-reload
~~~

Source installation does not create the `cm` symlink or enable services. Debian packaging supplies dependency installation and removal hooks.

## First use

~~~sh
sudo cm start
sudo cm status
sudo cm services
~~~

This starts CM with a passive policy. To choose an explicit web-server policy:

~~~sh
sudo cm profile show web-server --ssh-port 2222/tcp
sudo cm use web-server --ssh-port 2222/tcp
# Verify SSH access using a new connection.
sudo cm confirm
sudo cm enable
~~~

Use your actual management port. `--ssh-port` defaults to the configured `ssh` alias, initially 22/tcp.

Changes to an active policy normally require confirmation within 120 seconds. A transient systemd timer restores the previous policy if confirmation does not arrive. A fresh passive start needs no confirmation.

## Rules

~~~sh
sudo cm allow ssh
sudo cm allow https
sudo cm deny 5432/tcp --from 198.51.100.0/24
sudo cm allow out 443/tcp --to 203.0.113.10
sudo cm limit ssh --rate 4/minute --burst 4
sudo cm rules
sudo cm delete 3
~~~

Run `cm confirm` between live policy changes, or stage several changes and reload once. The examples above illustrate individual commands.

The outgoing example permits host-originated TCP traffic to destination 203.0.113.10:443. It is useful with a deny-outgoing policy. It neither opens incoming HTTPS nor forces another table to allow the traffic.

Connection limiting counts new TCP SYN packets. Authentication protection counts failed OpenSSH log events:

~~~sh
sudo cm protect ssh --failures 4 --window 10m --ban 30m --port 2222/tcp
sudo cm confirm
sudo cm ban 198.51.100.25 --for permanent
sudo cm bans
sudo cm unban 198.51.100.25
~~~

For permanent host-wide incoming bans after SSH failures, use `protect ssh --scope all --ban permanent`. CM does not infer authentication failures from TCP packets.

## Information

~~~sh
cm memory
cm cpu --interval 1000
cm disk --json
cm inode
cm os
cm hardware
cm time
cm timezone
cm net addresses
cm net interfaces
cm net routes
cm net route get 203.0.113.10
cm net dns
cm net listeners
cm net public-ip --family 4
sudo cm logs --since 1h --lines 100
~~~

Public-IP lookup sends an explicit HTTPS request; other information commands do not contact a public IP service.

## Documentation

- [Tool overview](PROJECT_OVERVIEW.md)
- [Complete command reference](docs/COMMANDS.md)
- [Configuration and persistence](docs/CONFIGURATION.md)
- [Architecture and security boundaries](docs/ARCHITECTURE.md)
- [Operations and recovery](docs/OPERATIONS.md)
- [Testing](docs/TESTING.md) and [validation record](docs/VALIDATION.md)
- [Primary references](docs/SOURCES.md)
- [Security policy](SECURITY.md)

The test matrix is a deployment gate, not a security certification. Read the validation record for what has actually run.

Licensed under GPL-2.0-or-later.
