# Security policy and architecture

## Report a vulnerability

Do not post real audit logs, credentials, databases or exploitable details in a
public bug report. Use GitHub private vulnerability reporting if enabled on the
repository; otherwise arrange a private channel with the maintainer before
sending sensitive evidence. Include version, affected source, prerequisites,
impact and a minimal synthetic reproduction. No response SLA is promised.
The current source is prototype 0.2; there is no LTS/support guarantee.

## Prototype 0.2 changes

Primary signatures are a hash-checked bundled SigmaHQ subset, safe-loaded with
PyYAML and interpreted by a bounded explicit grammar. No eval, executable
plugins, automatic downloads or rule-driven commands
are used. Unsupported rules are inactive. Local ordered correlations and reader
health/policy signals supplement the pack. Ignore exceptions are account-local
presentation choices, with exact-context fingerprints by default and narrowly
constrained optional AppArmor prefixes; they never relax host security policy.
Bounded policy context is retained to explain matches. Private rolling diagnostic
files store stack locations/counts and RSS, not exception messages or raw events.
Their paths can still expose installation locations. Cooperative ingestion and
rendering limits reduce pressure but do not prove hard realtime responsiveness
or eliminate all memory growth. See docs/REBUILD-REVIEW.md for review boundaries.
Bounded complete EXECVE arguments are evaluated transiently in RAM. Matching
alerts can additionally save a bounded best-effort redacted argument view,
enabled by default for investigation and disableable in Settings. Unknown
secrets can remain in that private alert context. Plain GTK text and individually
escaped indexed values have no execution/open action or reconstructed command.
Arguments remain excluded from event summaries, notifications and diagnostics;
Copy is manual data export, never safe-to-paste code. See docs/ARGUMENT-CONTEXT.md.
Python offers no zeroization guarantee. The separate Sigma collection draft can increase secret
exposure in raw audit logs and log volume; global exec collection is opt-in.
See docs/SIGMA-ARGUMENTS.md for limits and review requirements.
Opt-in exact application journal services use existing permissions and one
bounded fixed journalctl worker; trusted scope/unit/UID fields are rechecked.
Three application keyword rules are isolated from auditd inputs. Raw messages
exist transiently in RAM, never in saved evidence or diagnostics. Only matching
message metadata is retained; no service is selected automatically. See
docs/APPLICATION-JOURNALS.md for stdout-attribution and collection limitations.

## Runtime boundaries

Skidplate is an ordinary-user local audit viewer. The GUI and app installer
reject root. The generated user service has UMask=0077 and NoNewPrivileges=yes.
The app has no HTTP endpoint, remote model, telemetry, package manager, feed
client, sudo call or automatic incident response. Local journal access uses
only fixed absolute journalctl arguments, bounded workers/output/time and no shell.
No eBPF collector, packet capture or DNS lookup is used.

Treat every log field as hostile data. Never execute it, interpolate it into a
shell, render it as markup, or read an arbitrary evidence-selected file. Log
sources are read-only O_NOFOLLOW/O_NONBLOCK regular files. Record/group/line
sizes, processing batches, worker concurrency, descriptor scans, correlation
maps and output counts are bounded. A fast producer, rotations, stale/missing
records, kernel loss and native decoders remain real limitations. Readability
and absence of alerts are not proof of coverage, auditd health or host safety.

The private state directory must be owned, non-symlink and 0700; the SQLite
file must be owned, private, regular and single-link. Parameterized SQL handles
log fields. Seven-day retention and 5000-event/2000-alert caps apply. State is
plaintext, not an encrypted evidence vault or sandbox against the account owner.
Legacy state/database fallback preserves history without implicit merges.

Summaries exclude argv, proctitle, raw CWD and file contents. Up to eight
lexically resolved PATH targets/roles (512 characters each), numeric identity,
operation/ABI/result, captured unit and endpoints can be retained. Underlying
raw audit logs may contain unredacted secrets/argv independently of Skidplate.
Matching alert details save bounded, best-effort redacted argv context by default;
unknown secrets can remain. Disabling this setting affects future findings only.
Copied ignore-exception descriptions can outlive alert retention until edited or
deleted. See [argument context and privacy](docs/ARGUMENT-CONTEXT.md). Fixed numeric
ptrace/BPF/effective-UID selectors are derived from supported ABI arguments;
raw syscall arguments and supplied derived selectors are discarded from retained
fields. A separate transient Sigma mapping exposes only verified numeric
syslog/personality a0 and bounded complete EXECVE argv; no generic pointer or
raw command text enters saved event summaries; redacted alert details are a
separate explicitly documented privacy tradeoff. Precise
snoozes hash stable pre-truncation context; hashes are not encryption or log
authenticity. More metadata can expose private paths/accounts to a compromised
reader account. Never upload real history as a test fixture or diagnostic.

Evidence uses plain GTK text APIs and fixed foreground/weight tags, never
markup, hidden text, links or evidence-selected properties. Highlighting uses
Unicode offsets and caps styling at 256Ki characters/2048 spans, without
truncating displayed/copied evidence. Field colors do not establish safety or
authenticity. Clipboard export requires an explicit click.

Process/socket observations are read-only, bounded and transient. PID directories
for namespace holder matching are pinned with O_DIRECTORY/O_NOFOLLOW and identity
and descriptors rechecked. Investigation checks host, executable, login/session
and process-start consistency. Shared/inherited descriptors, permissions, PID
reuse, namespaces and races limit association. No argv/environ/memory or target
executable content is read. No signals, firewall changes or quarantine execute.
Saved connect evidence is separate from current socket snapshots.

Correlations isolate hosts and live/history, require supported numeric identity,
and cap transient state. Most process chains require exact executable; the
root-exec transition deliberately compares executables at the same PID/session
and has no historical process-start token. Exec/daemon/source/error resets and
time gates restrict joins. Names, UID requests, periodic connections and nearby
events remain heuristics, not proof of exploit, C2 or causation. Weak signals
remain Medium. Rule muting/snoozing can suppress findings/notifications by design.

## Installation boundary

`tools/install.py` copies only a fixed runtime source/asset set beneath an owned
prefix. It rejects root, control characters in paths, symlink ancestors/targets
and unsafe install directories; generated desktop/systemd paths are escaped for
their respective formats. It invokes no shell, systemctl, auditctl, sudo or
network client. It does not install system dependencies, grant log access,
start/stop services or migrate history. Upgrade preserves the old app payload;
launcher/unit customizations need separate backups. Installation can partially
apply on error. The source checkout/installer is trusted code the user chooses
to run, not a sandbox against its own owner.

## Optional privileged helper and policy drafts

The separately installed root-owned `org.skidplate.LogAccess1` helper has one
fixed EnableRead method. It derives caller UID from system D-Bus, requires
Polkit auth_admin on every request, and rechecks the sender before ACL changes.
Clients choose no paths/UIDs/commands. Root ancestors/log descriptors are pinned
and metadata checked; read grants target existing audit.log/numbered rotations
and directory traversal. Unrelated effective ACL rights are preserved. The
grant benefits every process of that account, can be partial on failure, and
is not durable rotation/reboot policy. The GUI does not install or elevate it.

Draft generators never install/load audit rules, create watched targets or
request root. They emit stable existing keys for compatibility, skip unsupported
paths and target x86_64 Arch/Omarchy assumptions. Review syscall names, ordering,
existing policy and privacy/volume effects before root-owned installation.
Machine-specific generated rules, rollback data and full auditd.conf files are
excluded from this repository. No code from a writable checkout should be run
as root. Any new privileged collector or automatic containment requires a
separate narrow design/security review and explicit administrator authorization.

## Review scope

Security review should prioritize data-to-code/markup injection, private-state
handling, resource bounds, process/event attribution, installation path escaping
and optional-helper authorization/filesystem targets. Tests use synthetic data,
not live network scans, root commands, host ACL changes or real audit policy.
Native GTK/desktop and kernel integration require separate runtime verification.
