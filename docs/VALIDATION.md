# Validation record

This file distinguishes implemented behavior from verification that has actually run.

## Local execution

During implementation:

| Check | Observed result |
| --- | --- |
| Strict GCC C17 build with conversion/shadow/format warnings as errors | Passed |
| C core boundary/parser/compiler tests | Passed |
| 32 offline CLI integration tests | Passed |
| GCC -fanalyzer build | Passed |
| Address/undefined sanitizer run, local leak scanning disabled | Passed |
| Local native Netlink/kernel packet/systemd checks | Blocked by workspace capabilities |

The implementation workspace cannot create network namespaces or use native Netlink routing/nftables operations, and its init is not systemd. LeakSanitizer also cannot inspect process threads there. These restrictions do not establish a test failure or a pass for those behaviors.

## GitHub verification

On 2026-10-07, all five jobs passed for source commit
[4126f6045f594e8c7130848cef8e7625e16753c3](https://github.com/The-Specter-X/command-center/commit/4126f6045f594e8c7130848cef8e7625e16753c3)
in [workflow run 37664125600](https://github.com/The-Specter-X/command-center/actions/runs/37664125600).

| CI job | Observed result |
| --- | --- |
| Debian 13 | Strict GCC build, core tests, 32 offline CLI tests and Debian package build passed |
| Debian testing | Strict GCC build, core tests, 32 offline CLI tests and Debian package build passed |
| Analysis on Ubuntu 24.04 | Clang address/undefined/leak sanitizers, GCC analyzer and strict Clang build/tests passed |
| Native on Ubuntu 24.04 | Real IPv4/IPv6 namespace packet tests and 4 read-only networking tests passed |
| Systemd on Debian 13 | Actual service lifecycle, real failed OpenSSH authentication, automatic bans/expiry, staged protection, timed rollback/confirmation, journal/reporting, APT scheduling, active/inactive upgrades, removal and purge passed |

The native job also verified passive initialization, foreign-table preservation,
rule precedence, connection meters, timed/permanent/scoped bans, UDP and reject,
drift repair, outgoing destination rules, isolation of established outbound
connections and logging quotas that preserve blocked verdicts.

The systemd fixture verified that an active SSH protector restarts during an
upgrade while the live policy table retains its handle. Inactive services stay
inactive. Removal resolves pending rollback and removes CM enforcement before
the executable disappears; purge preserves unrelated administrator files.

The run includes `packages-0` (Debian 13) and `packages-1` (Debian testing), each
with the main/shortcut `.deb` packages, `.buildinfo` and `.changes` files.
These are CI outputs rather than a separately signed release repository.

Use the workflow result for the exact commit being deployed. The observed pass
above applies to the linked source, not to untested future changes. Public-IP
option validation ran; an external public-IP service request was not part of CI.

## Deployment acceptance

A supported production release also needs an independent code/security review, target-image and upgrade testing, retained package provenance, an operational rollback procedure, and a maintenance owner.

Kernel/distro CI cannot prove behavior for every cloud firewall, third-party table, SSH build, routing topology or traffic load. Forwarding/NAT, general service-log filters and fleet management are outside the implementation's stated scope.
