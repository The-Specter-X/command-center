# Security policy

Command Center manages privileged server firewall state. Security reports should identify the affected commit/version, distro/kernel/library versions, a minimal reproducer and the impact.

Use GitHub private vulnerability reporting for this repository when available. Do not put working exploit details or server credentials in a public issue before coordinating remediation with the maintainer. General non-sensitive defects can be reported as ordinary issues.

## Supported boundary

The stated target is Debian 13/systemd with the declared library floor. The repository includes Debian-testing and Ubuntu-24.04 compatibility checks; support requires a passing result for the deployed commit and target-image validation.

Root, the kernel and installed system libraries are trusted. CM does not defend against a malicious root administrator, rewrite cloud security groups, manage container forwarding/NAT, or prevent volumetric DDoS exhaustion.

The detector consumes trusted OpenSSH journal events. Untrusted arbitrary service log messages and custom regex filters are outside its boundary. An all-port ban changes enforcement scope, not the source of authentication evidence.

## Engineering controls

The implementation uses strict schemas and numeric addresses, rejects unsafe file ownership/symlinks/links, uses bounded state, refuses setuid execution, avoids shells, checks native batches before applying, preserves foreign tables, and retains durable recovery records. The service units restrict privileges and writable paths.

Packet-meter/logging allocation and rate limits are tested separately from verdict behavior. Live changes normally have a timer-backed rollback. Structural drift is reported; dynamic set entries and counters are intentionally excluded.

See [architecture](docs/ARCHITECTURE.md), [testing](docs/TESTING.md) and [validation](docs/VALIDATION.md) for the precise mechanisms and verification limits.

No external security audit or enterprise certification is claimed. Production promotion requires review, target-image testing and an operational maintenance owner.
