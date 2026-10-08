# Testing

## Local checks

Install the dependencies from README, then run:

~~~sh
make -j2 all check
make CC=clang sanitize
make analyze
make clean
make CC=clang -j2 all check
make check-load
make fuzz-smoke
~~~

The normal check target runs core C boundary tests, 39 offline CLI tests, seven failure-injection scenarios, deterministic parser fuzz smoke and mocked kernel inspection/membership tests. It never changes host firewall, systemd or APT. Sanitizers include address/undefined behavior and leak checking when the environment permits leak scanning. GCC analysis compiles every implementation module with -fanalyzer.

Core tests cover numeric/network parsing, strict schemas, OpenSSH message parsing, failure windows, permanent/scoped bans, limits, native quoting, profile compilation, normalization and subprocess capture with closed standard descriptors.

Failure scenarios inject one-shot writes, renames, file/directory fsync and ENOSPC, kill a blocked commit/rollback/first loader apply, block package execution while rollback and bans progress, and deny mountinfo access during CPU/disk reports. Wrappers are linked only into build/test-faults; production binaries contain no test fault switches.

`check-load` fills 4096 bans and 4096 sources × 100 timestamps, round-trips strict state, processes a saturated 128-event batch and compiles 256 limit rules. JSON records size, elapsed time and peak process RSS; timings are evidence for that machine, not universal guarantees. Mocked transport tests use 10000 foreign table names, assert that hot-path snapshots query only names and the two owned tables, and measure membership checks at the full 4096-ban capacity. Native packet tests separately verify real kernel behavior.

`fuzz-smoke` uses Clang/libFuzzer with address/undefined sanitizers for 30 seconds. The pure target covers strict JSON/UTF-8/duplicate keys, address/service/duration parsing, OpenSSH messages, config/state/bundle round-trips and native compilation. It makes no kernel/file mutations. Seed generation uses temporary offline roots. The deterministic smoke is also run by normal/sanitized checks. Longer runs can use build/fuzz/fuzz-core and a retained corpus; a smoke pass is not exhaustive coverage.

Offline tests cover defaults, stable numbering/order, filters/ranges, deduplication, aliases, lifecycle/boot separation, confirmation/deadlines, interrupted/reboot recovery, staging, missing/corrupt files, symlink/permission/duplicate-key rejection, missing checkpoint rejection, guard-condition lock contention, TCP alias validation, profiles, logging settings, updates/drop-ins and system reports.

## Read-only network checks

~~~sh
python3 tests/test_network.py ./build/command-center
~~~

These tests inspect current interface/address/route/DNS reports and verify real bound TCP/UDP sockets. They reject unsafe public-IP options without making a public HTTP request. The environment must permit read-only Netlink sockets.

## Kernel packet checks

~~~sh
sudo python3 tests/test_live.py ./build/command-center
~~~

The parent launches a child in private mount and network namespaces. The child verifies both namespace IDs changed, overlays /etc, /var/lib and /run with private tmpfs, and creates a veth-connected client namespace. Host configuration and host firewall objects are not modified.

It exercises real listening TCP/UDP services over IPv4/IPv6, passive start with existing filtering, ordinary rule order, connection meters, native timeout expiry, permanent/scoped bans, reject, drift recovery, foreign-table preservation, outgoing destination rules, isolation of established outbound traffic, logging throttling and managed cleanup.

Regressions deplete burst-10 buckets, idle beyond the former two-second timeout and count dropped raw SYNs over IPv4/IPv6 input/output. They also check metadata/depleted-meter preservation, stable ban-table handles for deltas, membership and ban-structure repair, missing-marker refusal and previous-boot inactivity.

This requires mount/network namespace privileges and a kernel supporting the tested nftables features. An unprivileged workspace cannot substitute string-generation checks for these packet tests.

## Actual systemd/OpenSSH/package checks

~~~sh
docker build -f tests/systemd/Dockerfile -t command-center-systemd .
docker run -d --name command-center-test --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp command-center-systemd
docker exec command-center-test python3 /src/tests/systemd/test_systemd.py
docker exec command-center-test journalctl --no-pager -n 250
docker rm -f command-center-test
~~~

Run this fixture only in the disposable container. It boots systemd in a separate namespace and installs locally built Debian packages. It checks disabled-on-install defaults, actual lifecycle/enablement, transient timer rollback, confirmation, guard readiness, one-reader enforcement, real failed SSH authentications, ban expiry, protection while staging, corrupted desired-file service restart, journal views, time/network reports, APT schedules, loader restart, active-protector upgrade, inactive-service reinstall, preserved kernel policy on upgrade, removal/purge and unrelated-file preservation.

New cases fill both guard stores, verify cursor/drop progress without daemon exit, repair a removed native ban without new SSH events, block both post-commit service orderings, inject a failed guard job, and run timed rollback/SSH banning during a slow package check. Missing/corrupt state causes startup to fail after loading policy; explicit stop/removal must clean its tables. Purge checks canonical-file cleanup and edited-fragment preservation.

The fixture removes the Docker image's policy-rc.d inhibitor after image construction so package service actions operate under the running systemd. The container's SSH account/password are disposable fixtures, not deployment credentials. The packet test's internal apply/suspend commands are loader entry points; users should use start/stop.

## CI matrix

The GitHub workflow runs:

- Debian 13 and Debian testing: strict build, offline checks, binary Debian packages.
- Ubuntu 24.04: Clang address/undefined/leak sanitizers, GCC static analysis, strict Clang build.
- Ubuntu 24.04: private namespace packet tests and read-only networking tests.
- Disposable Debian 13 systemd container: actual service/SSH/package tests.

Actions are pinned to inspected commit SHAs. Package artifacts retain .deb/.buildinfo/.changes, exact source SHA, compiler/library versions, installed-package inventory, package contents, SHA256SUMS, offline results and load/query measurements. Additional artifacts retain fuzz, native/network and systemd/package test commands/results/logs. This is unsigned CI evidence; no signing key or signed repository is implied. Test diagnostics retain the system journal on service failure.

CI jobs have a 20-minute deadline. Direct dependency-install steps have an eight-minute deadline and use bounded network timeouts/retries so stalled package downloads cannot leave a check running indefinitely. Ubuntu runners use the canonical HTTPS archive when their image supplies an APT mirror list.

The workflow is a verification gate, not an automatic production deployment or a security certification. Add target-image testing for custom SSH builds, extra firewall owners, cloud networking and nonstandard server services.
