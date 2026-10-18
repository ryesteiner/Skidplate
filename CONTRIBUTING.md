# Contributing to Skidplate

Use synthetic fixtures and private temporary state. Never attach real audit
logs, SQLite databases, credentials, user paths or unredacted desktop evidence.
Use public issues for non-sensitive bugs; follow SECURITY.md for vulnerabilities.

## Layout

- `skidplate/`: parser, detector, storage, network snapshots and GTK interface.
- `assets/`: local CSS and SVG assets; no remote UI resources.
- `tools/install.py`: ordinary-user app packaging only.
- `tools/build_*_profile.py`: optional audit-policy draft generators.
- `deploy/log-access-button/`: separate optional privileged component.
- `tests/`: synthetic regression and GTK presentation checks.
- `docs/`: detection, collection, permissions and compatibility guides.

## Checks

With distribution Python/GI dependencies installed:

```sh
/usr/bin/python3 -m unittest discover -s tests
/usr/bin/python3 -I run.py --help
/usr/bin/python3 -I run.py --version
```

No test should scan a network, elevate privileges, alter host audit rules or
change live log permissions. Headless environments skip display-dependent
widgets; TextBuffer integrity checks still run. Use a disposable desktop/demo
session for visual/tray validation. Installed-app smoke tests use a temporary
prefix, not the developer's real application directories.

Keep evidence plain text, SQL parameterized, field/state/work limits explicit,
and live snapshots distinct from historical evidence. Do not add argv storage,
network clients, eBPF, root collectors or automatic containment casually.
Privileged components and policy changes require focused security review.

Use canonical Skidplate naming. Legacy state names and stable audit keys are
intentional compatibility interfaces (docs/compatibility.md), not rename targets.
Before release, run tests, review the exact diff/security boundaries, verify
README commands, ensure generated host data/secrets are excluded, confirm the
license and inspect the files that Git will publish. A CI pass is not a full
native desktop or live audit-policy test.
