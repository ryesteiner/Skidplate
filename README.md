# Skidplate


Skidplate is a local Linux audit-log viewer with behavior detections and
process/network context. It combines an Event Viewer style investigation flow
with a car-inspired dashboard and a system-tray icon.

**Prototype 0.2** uses a bundled SigmaHQ auditd subset as its primary signature
source, with explicit unsupported-rule reasons, manual ignore exceptions and
private crash/hang diagnostics. See [rebuild and manual review notes](docs/REBUILD-REVIEW.md).
This is a limited local Sigma backend, not full Sigma-language support.
The pack includes 30 auditd rules and three opt-in application rules. See
[argument matching and collection](docs/SIGMA-ARGUMENTS.md) and
[selected Python/Rails/Node.js journal services](docs/APPLICATION-JOURNALS.md).
Matching alerts can include [redacted, data-only argument context](docs/ARGUMENT-CONTEXT.md)
with matched Sigma selections. Unknown secrets may remain; persistence can be
disabled in Settings.

link to sigma detection rules: [(https://github.com/SigmaHQ/sigma)]

Built for Arch Linux and Omarchy; other Linux desktops need the same GTK3,
AppIndicator and auditd interfaces. This is a standalone application, not a
native Omarchy shell plugin. It runs as your normal user.

## Features

- Searchable events and grouped alerts with first/last seen times and counts.
- Highlighted users, paths, process IDs, endpoints and recorded outcomes.
- A resizable evidence panel, linked saved events, and separately labeled
  nearby activity. Current process/socket inspection stays distinct from history.
- Network connection counts and visible socket-holder PID/application details.
- Persistence, authentication, privilege, enumeration and remote-access signals.
- Rule toggles, High-only notifications, manual ignore lists and expiring snoozes.
- Explicit log-access, stale-data and partial-visibility states.
- Local processing: no telemetry, cloud service, threat-feed downloads, eBPF,
  packet capture or automatic quarantine.

## Quick start

Use the distribution Python, with system GI bindings installed. On Arch:

```sh
sudo pacman -S --needed python python-gobject python-cairo python-yaml gtk3 libayatana-appindicator libnotify audit
```

From this checkout, preview synthetic data with disposable state:

```sh
/usr/bin/python3 -I run.py --demo
```

Install the reviewed application for your user:

```sh
/usr/bin/python3 tools/install.py
systemctl --user daemon-reload
systemctl --user enable --now skidplate.service
```

The installer creates the app, launcher, desktop entry and user-service file;
it does not start services, install dependencies, grant permissions or change
audit rules. The following systemctl commands enable/start the service.
See [INSTALL.md](INSTALL.md) for requirements, log access, upgrades, rollback,
uninstallation, custom paths and migration from the earlier local installation.
Do not run Skidplate or its installer with sudo.

## How to use it

1. Open Skidplate from the app menu or tray. Check whether the log is readable.
2. Start with Alerts or Behavior. High means review priority, not confirmed compromise.
3. Select a finding for saved user/process/path/result context. Drag the divider
   above the evidence to resize it. Copy exports the full plain text.
4. Choose **Inspect process & connections…** for a current read-only snapshot.
   Missing processes/sockets may reflect permissions, races or exited programs.
5. Mark reviewed after investigation, or snooze a precise repeated context for
   10 minutes, one hour or 24 hours. Snoozing keeps events and findings.

The default Important/High-focused alert view hides Medium findings; use
**All alerts** or **Behavior** for routine tool-use and weak timing signals.
The Rules & access page controls enabled detectors and notification preferences.

## Detection and collection are different

Detection code cannot see records auditd did not collect. Installing or restarting
Skidplate does not activate kernel audit rules. A readable file is not proof of
healthy auditd, complete collection, or a safe host.

See [detection coverage](docs/detections.md), [audit collection](docs/audit-collection.md)
and [log access](docs/log-access.md). Rule generators produce local review drafts;
no machine-specific generated rules or full auditd configuration are shipped.

## Data and limitations

History is local plaintext in a private user directory: seven days, up to
5,000 event summaries and 2,000 alert groups. Event summaries exclude command
arguments, proctitle and file contents. Matching alert details can save bounded,
best-effort redacted argument context by default; unknown secrets can remain.
Disable this in Settings for future alerts. Existing saved context is not
purged, and copied ignore-exception descriptions can outlive alert retention;
see [argument privacy and controls](docs/ARGUMENT-CONTEXT.md).
Target paths, account names, executable paths and endpoints can also be sensitive.
Underlying auditd logs may contain unredacted arguments independently of this app.

Fresh installations use `~/.local/state/skidplate/skidplate.sqlite3` (or
`$XDG_STATE_HOME/skidplate`). Existing legacy history is preserved through an
explicit compatibility fallback; see [naming and migration](docs/compatibility.md).
Do not upload real logs, databases or screenshots containing private evidence.

No packet IDS, complete process tree, general CVE-exploitation proof, lossless
collector or tamper-resistant root agent is provided. See [SECURITY.md](SECURITY.md).

## Development

```sh
/usr/bin/python3 -m unittest discover -s tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for structure, offline tests and security
invariants. GitHub CI runs synthetic tests on an isolated hosted runner. Native
tray/desktop integration and real audit coverage require separate host testing.

## License

MIT. See [LICENSE](LICENSE). System dependencies retain their respective licenses;
they are not bundled with this repository.

Bundled SigmaHQ detection rules retain **DRL-1.1** and author attribution; see
[the rule license](rules/sigma/LICENSE.Detection.Rules.md). They are distinct
from the MIT-licensed application code.
