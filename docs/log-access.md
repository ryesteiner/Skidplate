# Audit-log access

The GUI runs as your ordinary account and only reads existing logs. Check both
file and directory access; directory `x` means traversal, not executing files.
A one-time per-file ACL may stop working after auditd resets permissions,
rotates to a new inode or the host reboots. Skidplate retries without bypassing
permissions. A readable log does not verify active rules or daemon health.

## Durable administrator-managed access

An administrator can configure auditd's supported `log_group` setting with a
dedicated read-only group such as `skidplate-log`, corresponding directory
traversal, and compatible local tmpfiles policy. Inspect existing groups,
configuration/ACLs and package defaults before making that change. Do not
replace auditd.conf or tmpfiles wholesale with another machine's configuration.
Do not add the reader to root/wheel or make logs world-readable. A full logout
may be required for new group membership; restarting the app alone can retain
old supplementary groups. Verify again after natural rotation and reboot.

Group membership grants raw-log reads to all processes under that account,
not just Skidplate. It does not inherently grant root, but exposes sensitive
usernames, paths and possible command arguments. Preserve administrator backups
and a reviewed rollback for group, auditd and directory policy changes.

## Optional authenticated read-access button

`deploy/log-access-button/` contains a separate fixed-purpose system D-Bus/
Polkit helper. The ordinary-user installer does **not** install it. It derives
the caller UID from the bus and authenticates an administrator on every request;
clients cannot choose a path, UID or command. It grants that account read access
to root-owned existing audit.log/numbered rotations plus directory traversal.
There are no default ACLs, new groups or durable boot/rotation configuration.
It may need to be requested again after rotation/reboot. Partial grants may
remain on error; inspect/revoke the specific account entries when appropriate.

If selecting this option, inspect the helper, its policy and unit first. From
this checkout, an administrator can install reviewed copies root-owned:

```sh
sudo install -o root -g root -m 0755 deploy/log-access-button/helper.py /usr/local/libexec/skidplate-log-access
sudo install -o root -g root -m 0644 deploy/log-access-button/skidplate-log-access.service /etc/systemd/system/skidplate-log-access.service
sudo install -o root -g root -m 0644 deploy/log-access-button/org.skidplate.LogAccess1.service /usr/share/dbus-1/system-services/org.skidplate.LogAccess1.service
sudo install -o root -g root -m 0644 deploy/log-access-button/org.skidplate.LogAccess1.conf /etc/dbus-1/system.d/org.skidplate.LogAccess1.conf
sudo install -o root -g root -m 0644 deploy/log-access-button/org.skidplate.logaccess.policy /usr/share/polkit-1/actions/org.skidplate.logaccess.policy
sudo systemctl daemon-reload
```

Check parent directories exist and are root-owned/not user-writable; create a
missing `/usr/local/libexec` administratively if needed. Back up pre-existing
targets before replacing them. Review distro D-Bus configuration reload needs;
do not restart the system bus casually. The service activates on a button
request; inactive when idle is normal. No persistent enable operation is needed.
Never run the helper directly from the writable checkout with sudo.

Existing helper users do not need reinstall merely for this application rename:
its bus name, action and fixed installed path are unchanged. App uninstallation
does not remove/revoke system helper or ACL changes; an administrator must stop
it, remove the exact installed files and review specific ACL entries separately.

References: [auditd log_group](https://man.archlinux.org/man/auditd.conf.5.en),
[ACL semantics](https://man.archlinux.org/man/acl.5.en),
[systemd tmpfiles](https://www.freedesktop.org/software/systemd/man/latest/tmpfiles.d.html).
