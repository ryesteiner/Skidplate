# Install Skidplate

## Requirements

- Linux desktop with GTK3, notification support and a StatusNotifier/AppIndicator tray.
- Python 3.10 or newer, PyGObject, Pycairo, GTK3, AyatanaAppIndicator3 and libnotify GI bindings.
- A readable regular raw/enriched audit log for real monitoring; auditd and
  suitable kernel rules for host collection. No root GUI is supported.
- systemd user services for optional background/autostart integration.

Arch/Omarchy dependencies:

```sh
sudo pacman -S --needed python python-gobject python-cairo gtk3 libayatana-appindicator libnotify audit
```

Optional authenticated log-access helper: `acl`, `polkit` and the system D-Bus
are additional prerequisites. The helper is not installed by the app installer.
Other distributions use their own package names; native GI libraries are system
packages, not dependencies that this project downloads through pip.

## 1. Obtain and inspect the source

Clone your chosen Skidplate repository, or extract its source archive. Open a
terminal inside that directory. The instructions are relative to the checkout,
so no specific username, GitHub owner or checkout location is required.
Inspect `tools/install.py` and source before executing code. This project does
not use curl-to-shell installers, GitHub Pages or install-time network requests.

## 2. Preview without audit-log permissions

```sh
/usr/bin/python3 -I run.py --demo
```

The demonstration uses synthetic events and disposable state. No host process
association is attempted. The source selector can read a real log only if you
explicitly select one. Hide closes the window to tray; Quit ends the app.

## 3. Install as your ordinary user

```sh
/usr/bin/python3 tools/install.py
```

Default layout:

| Resource | Location |
|---|---|
| Application payload | `~/.local/share/skidplate/` |
| Executable launcher | `~/.local/bin/skidplate` |
| App-menu entry | `~/.local/share/applications/skidplate.desktop` |
| User-service unit | `~/.local/share/systemd/user/skidplate.service` |
| Fresh state/database | `${XDG_STATE_HOME:-~/.local/state}/skidplate/skidplate.sqlite3` |

The payload is a separate reviewed copy; moving/deleting the checkout does not
break it. Add `~/.local/bin` to PATH if needed, or run that launcher by its full
path. Existing install targets require `--upgrade`; symlink installation
ancestors/targets and foreign or group/world-writable directories are refused.
Installation can leave partial files on failure: inspect the reported paths
before retrying. It makes no systemctl, sudo, package-manager or auditctl calls.

`--prefix /absolute/path` stages the same `bin/` and `share/` layout elsewhere.
A custom prefix is not automatically registered with desktop/systemd search
paths. If XDG_DATA_HOME differs from `~/.local/share`, put the generated desktop
entry and unit in your configured application/unit directories after review.
Do not add an arbitrary writable prefix to privileged search paths.

## 4. Start or enable autostart

If migrating from the previous local version, first follow the legacy-service
section below. Otherwise:

```sh
systemctl --user daemon-reload
systemctl --user enable --now skidplate.service
systemctl --user status skidplate.service --no-pager
```

Or launch the app manually from the menu, or:

```sh
~/.local/bin/skidplate
```

Use one real instance per state directory. A private lock prevents concurrent
instances from sharing history. The service has UMask=0077 and
NoNewPrivileges=yes. It does not run as root. It must run inside a graphical
user session with the appropriate display/session environment.

## 5. Make logs readable and configure collection separately

```sh
test -r /var/log/audit/audit.log
```

A failed test means log access needs administrator setup. Never compensate by
making the logs world-readable or running the GUI with sudo. Read
[log access](docs/log-access.md) before selecting a permission model.

For a readable exported log:

```sh
/usr/bin/python3 -I run.py --source /absolute/path/to/exported-audit.log --state-dir /absolute/path/to/private-test-state
```

Use a new private directory for imported evidence; do not mix it into live
history unintentionally. For kernel collection, read
[audit-collection.md](docs/audit-collection.md). Installation does not enable
missing exec/connect/UID-change records or verify audit daemon health.

## Upgrade

Review the new source and tests, then:

```sh
systemctl --user stop skidplate.service
/usr/bin/python3 tools/install.py --upgrade
systemctl --user daemon-reload
systemctl --user start skidplate.service
```

If running manually, quit from the tray before replacing the payload. The old
application payload is retained as `~/.local/share/skidplate.backup-<number>`.
History is not copied, renamed, deleted or reset by the installer. Preserve a
private SQLite backup with the application stopped before major upgrades.
Do not commit the backup to Git. Unit/launcher files are regenerated; keep
copies yourself if you customized them. An upgrade failure can leave a partial
installation; it is not a fully transactional package manager.

To roll back, stop the service, preserve the failed payload, and restore the
reported previous payload to `~/.local/share/skidplate`. Restore any customized
launcher/unit copies, reload user units and start again. Keep state backups:
rolling back application code does not roll back future database changes.

## Uninstall the application

For the default prefix, stop the service/quit the tray first:

```sh
systemctl --user disable --now skidplate.service
rm -- ~/.local/bin/skidplate
rm -- ~/.local/share/applications/skidplate.desktop
rm -- ~/.local/share/systemd/user/skidplate.service
systemctl --user daemon-reload
```

After checking the path, remove only `~/.local/share/skidplate/` (the application
payload), and any old `skidplate.backup-*` payload directories you no longer
need. Private history is deliberately retained; delete its specific directory
only if you intend to erase it. Uninstalling the app does not revoke log-read
permissions, uninstall the optional system helper or remove audit rules; those
administrator changes require their own reviewed rollback.

## Troubleshooting

- **Monitoring unavailable / permission denied:** check access to both log and
  parent directory; rotation can replace the inode. See the access guide.
- **Rule coverage unverified:** readability and enabled detectors do not prove
  that the kernel collects the events those rules need.
- **No process holder:** ordinary-user restrictions, exited processes and scan
  caps can prevent association. Do not run the whole app as root.
- **Already running:** use the existing tray, or quit/stop that instance first.
- **Missing gi/typelib/cairo:** install the system packages and use `/usr/bin/python3`.
- **No display / no user bus:** start from the desktop session, not a headless
  shell. Native UI behavior must be tested there.

Primary interfaces: [systemd user unit search paths](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html),
[desktop entry Exec quoting](https://specifications.freedesktop.org/desktop-entry/latest/exec-variables.html),
[Arch AppIndicator package](https://archlinux.org/packages/extra/x86_64/libayatana-appindicator/).
