# Primary implementation references

The implementation uses supported upstream interfaces. These references are
documentation, not vendored source or compatibility promises for future versions.

- [Netfilter nftables project](https://www.netfilter.org/projects/nftables/index.html)
- [libnftables C API](https://manpages.debian.org/testing/libnftables1/libnftables.3.en.html)
- [libnftables JSON schema](https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html)
- [nftables manual](https://netfilter.org/projects/nftables/manpage.html)
- [Atomic rule replacement](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)
- [Native per-source meters](https://wiki.nftables.org/wiki-nftables/index.php/Meters)
- [systemd journal API](https://www.freedesktop.org/software/systemd/man/latest/sd_journal_open.html)
- [systemd journal match semantics](https://www.freedesktop.org/software/systemd/man/latest/sd_journal_add_match.html)
- [systemd service readiness](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html)
- [systemd timer settings and reset semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html)
- [unattended-upgrades upstream](https://github.com/mvo5/unattended-upgrades)
- [Debian unattended-upgrade manual](https://manpages.debian.org/testing/unattended-upgrades/unattended-upgrade.8.en.html)
- [Linux procfs counters](https://docs.kernel.org/filesystems/proc.html)
- [statvfs](https://man7.org/linux/man-pages/man3/statvfs.3.html)
- [Filesystem Hierarchy Standard](https://specifications.freedesktop.org/fhs/latest-single/)
- [libnl routing interfaces](https://www.infradead.org/~tgr/libnl/doc/route.html)
- [systemd manager D-Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html)
- [systemd-resolved D-Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html)
- [Journald storage and retention](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html)
- [libcurl easy API](https://curl.se/libcurl/c/)
- [Docker firewall behavior](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [UFW framework](https://manpages.debian.org/trixie/ufw/ufw-framework.8.en.html)
- [nftables logging flags](https://wiki.nftables.org/wiki-nftables/index.php/Logging_traffic)

OpenSSH journal message coverage must be verified with actual failures on each
supported server image, including `sshd-session` formats. New parser coverage
requires fixtures and an end-to-end target-image test to avoid double counting.
