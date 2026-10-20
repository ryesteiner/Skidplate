# Prototype 0.2: Sigma, noise controls and diagnostic review

This source remains a prototype, not a production EDR or a lossless SIEM.
Installing or upgrading a running instance is a separate step; see
[INSTALL.md](../INSTALL.md).

## Detection architecture and provenance

SigmaHQ's `sigma` repository is the primary signature source. `rules/sigma`
contains a reviewed public auditd subset and `snapshot.json` lists source URLs,
retrieval date and per-file SHA-256 values. The public retrieval did not expose
a trustworthy whole-repository commit; no commit pin is claimed. Some public
pages flattened YAML, so those rules are cataloged as not bundled instead of
inventing source formatting or provenance. This is not all SigmaHQ rules.

### Local archive import, 2026-10-20

The supplied `localSigmaRules/sigma_all_rules` archive contains 149 Linux rules,
including 27 auditd rules. Its version file declares a 2026-07-09 release and
commit `552f3fee420ef232a8e5790c4fae591847e32347`; that declaration has not been
independently authenticated. Fifteen additional auditd YAML files were copied
byte for byte into the fixed pack with SHA-256 hashes and source attribution.
Existing rules were preserved, including three absent from the older archive.
The local archive is excluded from Git and is not scanned by the runtime.

At import time the pack contained 30 auditd rules: 17 supported and 13 inactive.
The subsequent bounded argument backend supports all 30; see
[SIGMA-ARGUMENTS.md](SIGMA-ARGUMENTS.md) for privacy and collection limits.
Six newer catalog entries remain not
bundled because their files are absent from the supplied snapshot. The other
122 Linux rules require different telemetry; they are not auditd rules and
were not enabled or translated by guesswork. Installing a rule does not enable
its kernel collection requirements. In particular the upstream C2 rule matches
`key=susp_activity`, not arbitrary network activity; its title is not evidence
of C2. The webshell rule assumes effective UID 33, which is not automatically
the correct web-server UID on Arch. No host audit configuration was changed.

The rules retain DRL-1.1 licensing, their authors, status, false-positive guidance
and source. Application code stays MIT. Match details and desktop notifications
include author attribution. See `rules/sigma/LICENSE.Detection.Rules.md`.

`skidplate/sigma_engine.py` is a bounded offline execution backend for maps,
OR-lists, literal strings, Sigma `*`/`?` patterns, startswith/endswith/contains,
boolean conditions, parentheses, and `1 of`/`all of` selection groups. It does
not implement the entire Sigma specification. It executes no condition as code,
loads no plugins and downloads nothing. YAML is safe-loaded from the hashed
bundled pack, not from audit events. PyYAML is the only new runtime dependency.
pySigma was assessed as a parser/query converter; it is not needed to execute
this deliberately limited backend. No GitHub sign-in or Python package download
is needed; Arch's `python-yaml` supplies the dependency.

Rules requiring raw arguments, regex, aggregation, different log sources or
other unsupported semantics were initially inactive with a reason. Bounded
complete argv and verified numeric selectors are now supported as documented
in SIGMA-ARGUMENTS.md; regex/aggregation/other log sources remain unsupported.
A rule's supported
status means backend compatibility, not verified audit collection. Numeric
syscall normalization uses explicit ABI maps only. Rule matching stays within
one captured record; unrelated PATH records are never flattened together.
Relative PATH names are resolved lexically only when captured CWD or one
unambiguous parent establishes an absolute base. Targets are never opened.

`Detector` defaults to Sigma. Existing ordered behavior correlations, policy
denials, authentication bursts, explicit network watchlist and collection health
remain labeled local supplements. Prototype key/path signatures are not emitted
as a second default signature set.
Direct high-risk evidence (risky root execution, anonymous execution, memory
writes, BPF loads and temporary executables connecting) also remains as local
supplements so the limited upstream pack does not silently remove those signals.
No BPF collector is used. Legacy algorithms remain explicitly
selectable with `mode='prototype'` for regression comparison; there is no silent
fallback if the pack is broken. Identical Sigma logic shares a finding and
retains all matching author/source metadata. Distinct rule logic or behaviors
remain separate; severity is not increased because more rules matched.

Upstream titles can imply changes or execution more strongly than the raw
matching condition establishes. Details explicitly say to verify captured
operation, success/failure and PATH roles. Low/informational upstream findings
remain low priority; critical is displayed at this UI's highest level, High,
while the original level remains in evidence. Missing telemetry is not safety.

## Manual noise controls

`skidplate/noise.py` stores at most 256 exceptions in the existing private SQLite
database. Exact exceptions match a rule and SHA-256 of its pre-truncation event
context. Optional policy prefixes additionally require exact host, executable,
AppArmor profile, operation and denied permission. The prefix is literal,
absolute and manually previewed; it uses no regex or shell expansion.

Select a finding and choose **Ignore matching alert**. A reason is required;
choose expiry or until re-enabled. A broader AppArmor prefix requires a second
Save after preview. **Ignored alerts** shows conditions, reason, expiry, enabled
status, suppressed-match count and latest match; edit, disable or delete there.
Editing preserves existing expiry unless explicitly changed. Prefix matching
conditions are editable for an existing prefix exception. Replace an exact
exception by creating a new one if its context must change.

Reviewed is acknowledgement; snoozed is temporary popup suppression; ignored
hides matching findings and popups. Underlying events are still saved within
normal retention. Existing retained groups reappear when an exception expires
or is disabled. Matches suppressed while enabled do not retroactively create
new groups. Preview checks do not increment counts. Counts include matching
historical imports as well as new events. No automatic trust learning or policy
relaxation is performed. AppArmor continues enforcing the same restrictions.
Bounded policy context (up to 512 characters per field) is now retained to
explain policy exceptions. Event summaries exclude argv and file contents;
matching alerts can retain bounded redacted argv context by default as described
in [ARGUMENT-CONTEXT.md](ARGUMENT-CONTEXT.md).

## Responsiveness and memory review

The prototype parsed up to 256KiB per GTK tick and committed each event. That
can stall the UI under volume. `skidplate/ingestion.py` now reads at most 16KiB,
processes at most 64 work units or about 20ms, and drains bounded queues before
reading again. SQLite ownership stays on the GTK thread, with short ingestion
batches. Failed transactions requeue all consumed batch events, and resolver
cursors advance only after the commit. A single slow SQLite operation
can still exceed the cooperative budget; the budget is not a hard realtime
guarantee. Queue pressure remains in the log source, so long delays/rotation can
still cause coverage gaps. Resolver batches are consumed eight records per tick.

History refresh is every three seconds; stable GTK rows are reused; pending
scroll-restore callbacks are coalesced/cancelled when widgets are destroyed.
The socket table displays at most 500 rows, with the full bounded snapshot count
kept distinct. This reduces native row allocation and rendering pressure.
These are source-backed pressure fixes, not a claim that the previously
reported long-session leak has been conclusively reproduced or eliminated.

## Crash, error and hang diagnostics

`skidplate/diagnostics.py` creates private `diagnostics.jsonl` and `faults.log`
inside the selected state directory after the instance lock is acquired.
Diagnostics cover startup/shutdown, current RSS in KiB, thread and queue counts,
and exception class with frame locations. It deliberately omits exception
messages, source lines, locals and raw audit data. Files may expose source paths.
Each diagnostic stream is trimmed at roughly 1MiB at its next write/heartbeat.
Copy important diagnostics privately before the rolling history is overwritten.

A one-shot 30-second faulthandler timer resets with each GTK tick and dumps
thread locations on a stall. Fatal signals also attempt a Python traceback;
there is no upload or automatic restart/kill. Unexpected callback exceptions
leave monitoring explicitly in error instead of silently removing the timer.
An OOM/SIGKILL or system failure cannot be guaranteed to leave a final traceback;
the last health sample and normal system journal are separate evidence.

Start a synthetic demonstration from a graphical session with
`/usr/bin/python3 -I run.py --demo`. Its diagnostics live in disposable demo
state and are removed on exit. Real monitoring uses the documented private
state/legacy-state fallback. Keep diagnostics private; sharing is manual.

## Manual code-review map

- `sigma_engine.py`: provenance/hash boundary, supported grammar, record-scoped
  matching and explicit unsupported-rule handling.
- `core.py`: Sigma default/supplement selection, author metadata, grouping and
  exact-context suppression before finding creation; event persistence remains.
- `noise.py`: fixed exception shapes, validation, expiry, reversible management,
  bounded cache and counter updates.
- `ingestion.py`: bounded backpressure, cooperative work budget and event retry.
- `diagnostics.py`: file metadata checks, redaction and watchdog lifecycle.
- `ui.py`/`widgets.py`: exception previews, attribution, limited rendering,
  callback guards and native-row reuse.
- `tests/test_sigma_noise.py`: actual default behavior, record isolation,
  unsupported fields, tampering, narrow exceptions, burst ingestion and privacy.
  Older detector tests explicitly exercise retained prototype compatibility.

No privileged helper, audit rule or AppArmor configuration changes are included.

## Validation on 2026-10-20

Codex Security reviewed the initial rebuild and two follow-up deltas before
their changed runtime code was executed; none had reportable security findings.
This was source review, not a dependency CVE scan or a host-policy assessment.
The final runtime source matched the reviewed snapshot byte for byte.

The final `/usr/bin/python3 -m unittest discover -s tests` ran 148 tests successfully,
with one display-dependent test skipped. Temporary-prefix installation,
upgrade/rollback payload preservation, independent installed rule loading,
launcher version reporting and desktop-entry validation also passed.
`git diff --check` passed.

A headless 20,000-event synthetic AppArmor-denial soak retained the 5,000-event
history cap and 30 alert groups. Sampled peak RSS stayed at 26,968 KiB at
5,000, 10,000 and 20,000 events. This measures detector ingestion, not native
GTK allocations or a long desktop session. A disposable Broadway GUI attempt
was blocked by this session's socket permissions. Native desktop/tray testing
and comparison with a captured long-session diagnostic remain necessary before
calling the memory complaint resolved. The existing running application was
not replaced or restarted.
