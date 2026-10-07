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

The repository's [Build and verify workflow](https://github.com/The-Specter-X/command-center/actions/workflows/ci.yml) is configured for:

- Debian 13/testing strict builds, offline tests and packaging.
- Clang address/undefined/leak sanitizers, GCC analyzer and Clang strict tests.
- Privileged IPv4/IPv6 namespace packet tests and native network reports.
- Actual systemd, OpenSSH authentication/journal and Debian package lifecycle.

Use the workflow result for the exact commit being deployed. An observed CI result will be recorded here after the run completes; configured jobs alone are not claimed as passed.

## Deployment acceptance

A supported production release also needs an independent code/security review, target-image and upgrade testing, retained package provenance, an operational rollback procedure, and a maintenance owner.

Kernel/distro CI cannot prove behavior for every cloud firewall, third-party table, SSH build, routing topology or traffic load. Forwarding/NAT, general service-log filters and fleet management are outside the implementation's stated scope.
