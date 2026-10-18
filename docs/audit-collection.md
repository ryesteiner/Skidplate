# Audit collection is an administrator task

Skidplate's normal-user installer does not change auditd or kernel audit rules.
Existing readable logs can be viewed immediately, but individual detections
need suitable records. Active detector toggles are not active collection policy.

Inspect before changing anything:

```sh
sudo auditctl -s
sudo auditctl -l
```

`enabled 1` permits changes; `enabled 2` is immutable until reboot. `lost` reports
kernel audit record loss and `backlog` the current queue. Watch for increasing
loss before expanding collection. No lossless collection claim is made.

## Optional local draft generators

These are Arch/Omarchy-oriented **x86_64 review tools**, not installers or a
portable audited policy for every host. Run as an ordinary user:

```sh
/usr/bin/python3 tools/build_audit_profile.py --output-dir build/audit
/usr/bin/python3 tools/build_persistence_profile.py --prior build/audit/60-skidplate.rules > build/audit/70-skidplate-persistence.rules
```

Outputs stay under ignored `build/`. Inspect every rule and skipped path;
validate against your live policy, existing rule ordering, filesystem/mounts,
exact audit userspace syscall names and kernel support. The base assumes
existing identity/sudo/systemd/module policy (as on Omarchy); on another host,
those watches need their own administrative configuration. Never create missing
startup files just to make them watchable. `--home` selects another simple
absolute home path; whitespace/unsafe audit syntax is rejected.

The base drafts cover root exec, direct IPv4/IPv6 connects and selected sensitive
interfaces/configuration paths. They do not add general non-root exec or
setuid/setreuid/setresuid collection, so those detections can have gaps. Adding
exec coverage records arguments in the raw audit log even though Skidplate drops
them. More collection also adds disk/CPU load and privacy exposure.

No generated host profile or full auditd.conf is shipped. A staged profile is
not proof of live coverage. No automatic root activation command is offered:
review exact target files and existing configuration before installing any draft
root-owned in `/etc/audit/rules.d/`. Avoid duplicate old/new profiles. An
administrator may use `augenrules --load` after that review, then inspect both
loader errors and `auditctl -s/-l`. Loads can partially apply before failure.
Do not use global `auditctl -D` to update or remove this app's rules.

Rollback files contain exact removals for the generated draft, not an inventory
of installed rules; compare first. File removal alone does not necessarily
remove already-loaded kernel rules. Immutable policy requires the normal
controlled reboot/load procedure. Never execute user-writable scripts as root.

Primary references: [auditctl](https://man.archlinux.org/man/auditctl.8.en),
[audit.rules](https://man.archlinux.org/man/audit.rules.7.en),
[auditd.conf](https://man.archlinux.org/man/auditd.conf.5.en).
