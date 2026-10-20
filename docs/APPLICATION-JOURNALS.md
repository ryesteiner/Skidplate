# Selected application journal services

Three original SigmaHQ rules from the supplied local snapshot are bundled:

| Product mapping | Rule | Priority |
|---|---|---|
| python | Python SQL Exceptions | Medium |
| ruby_on_rails | Ruby on Rails Framework Exceptions | Medium |
| nodejs | Potential RCE Exploitation Attempt In NodeJS | High |

These match exception/error text, not all Python/Ruby/Node processes or attacks.
SQL errors and Rails exceptions often mean application bugs. Node child_process
errors can come from legitimate Puppeteer usage. A configured product mapping
is your choice of rule source, not verified application identity. Matches do not
prove exploitation, execution or a successful network connection.

## Configure explicit services

After installing the updated app, open Settings, **APPLICATION ERROR JOURNALS /
OPT IN**. Enter up to eight exact services separated by semicolons, then Apply:

```text
user:python:my-python-app.service; system:nodejs:my-node-app.service
```

Those are examples; substitute actual services you operate. Use `ruby_on_rails`
for Rails. `user` reads your own user-service journal; `system` reads the system
service journal using only your existing permissions. Empty selection disables
the reader. No service is preselected, installed, started, restarted or changed.
Wildcard units, arbitrary journal options, paths and duplicate source mappings
are refused. Saved malformed selections show an explicit Settings error.

Selection changes and app restarts start reading from now; there is no automatic
historical backfill or persistent cursor across restarts. During a session each
source has its own cursor, advanced only after SQLite commit. A busy batch can
temporarily prevent reconfiguration; try again after it drains. Status beneath
the entry shows reads, possible backlog or unavailable access. A successful
empty read does not prove that the service exists or is logging exceptions.
Journal rotation, permission restrictions, filters, missing fields and reader
limits can leave gaps. Do not run the GUI as root or grant broad journal access
just to silence an unavailable status.

## Privacy and limits

The fixed argument-list journalctl command reads only selected exact trusted
unit fields (and your UID for user sources). Returned origin fields are checked
again; untrusted SYSLOG_IDENTIFIER text is not an origin check. No shell, pager,
_CMDLINE, remote journal, dynamic executable command, log-level change or
privilege request is used. Journal credentials can describe the parent that
opened a stdout stream rather than the child that emitted a message; they are
context, not an audited process-causality claim. Journal entries are kept
separate from auditd host/process correlations.

All journal priorities are read within the selected units: application errors
written to stdout may have informational journal priority. Only rule-matching
entries contribute metadata/events to Skidplate's bounded shared history. Other
messages are discarded. Regex is not used for matching and raw text is never
executed or displayed. Matches save rule attribution, static matched indicators,
unit/product/scope and bounded journal subject metadata, plus a context hash.
Raw message text, SQL queries, tokens, stdout and stack traces are not saved in
the database, notifications or app diagnostics. The original system journal
still contains whatever the application logged.

Messages can contain secrets: they exist transiently in RAM and Python offers
no prompt zeroization guarantee; swap/core dumps and same-account compromise
remain risks. No terminal keystrokes, sudo password prompts, environment or
other process memory are collected. Existing application logs may themselves
contain secrets independently of this reader.

One application-query worker runs at a time, with at most eight sources, 100
entries per batch, 16KiB per message and the existing combined 1MiB/3-second
query limits. Invalid/duplicate/binary metadata or oversized records cause an
explicit unavailable source state rather than guessing. Per-entry matching and
batch processing are bounded; very chatty services can fall behind. There is no
claim of lossless collection or long-session GUI verification. Ignore, snooze,
rule toggles, High-only popups and the notification cap apply as usual.

Primary references: [journalctl match and access semantics](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html),
[trusted journal fields, messages and stdout credentials](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html).
Original YAML, hashes, authors and archive provenance remain in rules/sigma.
