# Operations and recovery

## Install and activate

Build/install the Debian packages as described in README. Package installation leaves the loader disabled and stopped. Use `command-center` if the optional cm shortcut conflicts with another command.

~~~sh
sudo cm start
sudo cm status
sudo cm enable
~~~

A fresh start is passive. Enable makes the committed policy load at future boots. Stop/disable have independent meanings; use `disable --now` when both current enforcement and startup should stop.

Choose the management port explicitly when adopting a restrictive profile. For a server using SSH on 2222:

~~~sh
sudo cm profile show ssh-only --ssh-port 2222/tcp
sudo cm use ssh-only --ssh-port 2222/tcp
# Test a new SSH connection before accepting the change.
sudo cm confirm
~~~

If confirmation does not arrive, the previous policy is restored. The old session is not sufficient evidence that a new session can connect. The confirmation default is 120 seconds and can be changed per operation.

## Batch edits

~~~sh
sudo cm allow ssh --stage
sudo cm allow https --stage
sudo cm deny 5432/tcp --stage
sudo cm config validate
sudo cm check
sudo cm reload
sudo cm confirm
~~~

The running monitor uses applied settings throughout staging. Reload is the explicit approval boundary. Reload while stopped commits settings without turning filtering on.

## Inspect behavior

Use `status` for current activation, boot startup, table presence, service state, numbered desired rules and drift. Use `rules` to inspect order and IDs. Ordinary rules are first-match; use move to put a specific deny before a broad allow.

A foreign table may still drop traffic that CM allows. Host input/output rules do not cover bridge-container forwarding. Inspect Docker's firewall policy and cloud/network controls with their own owners when diagnosing those paths.

CM reserves its two table names. Do not use those names for another application. CM never flushes foreign tables; an external global flush can nevertheless remove CM's objects.

## Recovery actions

| Situation | Action |
| --- | --- |
| A pending change still has management access | Test a new connection, then confirm |
| A pending change is wrong | Rollback, or wait for its timer |
| An interrupted transaction is reported | Recover |
| Desired settings were edited outside CM | Validate/check, then explicit reload |
| Desired file is malformed and should be discarded | Config restore |
| Established configuration/state files are missing or invalid | Resolve existing intent/pending records, then recover checkpoint |
| The committed checkpoint is missing | Restore a trusted backup; boot refuses to initialize an existing installation as passive |
| Managed kernel structure was edited/flushed | Inspect status, then reload |
| Protector is unhealthy after policy committed | Inspect logs/service diagnostics; retry protection or restart the guard |
| CM should stop this boot but resume next boot | Stop |
| CM should stop and remain off | Disable --now |

Recovery uses durable records, not guessed defaults. Keep a console/out-of-band recovery path for restrictive policy testing. CM cannot recover a failure caused by an upstream firewall that prevents any management access.

For service diagnostics:

~~~sh
sudo cm logs --since 1h --level debug
sudo systemctl status command-center.service command-center-guard.service
sudo journalctl -u command-center.service -u command-center-guard.service
~~~

A failed service-control step can follow a successful kernel/configuration commit. Status exposes this split; do not assume an error means no change happened.

## Logs and retention

CM sends administration messages to the system journal and optionally logs selected packets through the kernel. Keep packet logging off or low for ordinary operation; higher settings are intended for diagnosis. Logging has its own rate cap so repeated drops do not create an unbounded packet log.

Journald handles file rotation and space/age limits. CM does not periodically truncate a private log or vacuum a shared journal. To choose a server-wide policy, an administrator can install a journald drop-in such as:

~~~ini
[Journal]
SystemMaxUse=256M
RuntimeMaxUse=64M
MaxRetentionSec=14day
~~~

These are examples, not CM-installed defaults. They affect all services using that journal. Retention must account for incident investigation and the maximum authentication-counting window.

If a saved SSH journal cursor has been rotated away, CM records the gap and resumes from the current tail; it does not invent missing failures.

## Updates

~~~sh
sudo cm updates enable
sudo cm updates reboot off
sudo cm updates schedule 03:15
cm updates status
sudo cm updates check
~~~

CM's fragment controls periodic unattended installation and reboot policy. Upstream APT files retain origins, exclusions and package policy. Isolation blocks ordinary outgoing update access until explicitly relaxed.

CM refuses an owned update/drop-in file that was changed outside its expected format. Move administrator policy to a separate upstream fragment rather than asking CM to overwrite it.

## Backups and removal

Back up /etc/command-center and /var/lib/command-center with root-only access while no mutation is running. The latter contains source addresses, attempt history and journal cursor data. It can be sensitive operational information.

Package upgrades preserve the running kernel policy and do not restart the oneshot loader. A running protector is restarted with the new executable; inactive services stay inactive. Package service actions respect Debian's policy-rc.d. Stop CM explicitly before removal if administrator policy inhibits service actions.

Removal first resolves a pending rollback, then stops the loader/monitor and removes only CM enforcement. Configuration/state remain for reinstallation. Purge removes known CM data and owned APT/timer files, while preserving unrelated files in the same directory.

Standalone make install has no dpkg lifecycle hooks. Stop/disable CM explicitly before removing its binary/units.

The beta schema and this schema-2 redesign differ. Do not assume package replacement automatically converts an old beta policy; use a fresh explicit configuration and validate it before activation.
