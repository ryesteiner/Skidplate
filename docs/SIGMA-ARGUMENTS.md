# Bounded Sigma argument matching and collection draft

All 30 bundled auditd rules are now compatible with the backend. Six cataloged
rules still have no source file. Backend compatibility does not prove that the
kernel collected the records required by any particular rule.

## Privacy and execution boundary

The normal sudo password prompt reads the password from the terminal, not from
the command's argv. This matcher does not collect keystrokes, inspect another
process's memory or environment, or decode TTY input payloads. A password/token
explicitly passed as a command argument is different: auditd may put it in the
root-owned raw audit log, and this matcher may briefly process it in RAM.

EXECVE argument strings are kept in a separate transient Record mapping, not in
ordinary retained fields. The subsequent investigative-context feature saves
a bounded, best-effort redacted view with matching alerts by default; see
[ARGUMENT-CONTEXT.md](ARGUMENT-CONTEXT.md) for the setting and privacy limits.
Unknown secrets can remain. Disabling that setting restores no-argument
persistence for future findings. Raw argument vectors are never added to event
summaries, notifications, exception values or application diagnostic logs.
Context hashes distinguish
manual exceptions but do not encrypt a secret or resist guessing low-entropy
arguments. Python does not guarantee prompt zeroization of strings; process
core dumps, swap and a compromised same-account reader are separate risks.
This is an ordinary-user application, not a secret-handling enclave.

No argument is executed, interpolated into a shell, rendered as markup, or used
as a path to open. Collection adds no application privilege, helper method,
listener or log-read permission. It does increase sensitive data handled in RAM.

## Supported argument view and deliberate limits

- Complete single-record EXECVE only, with an explicit argc from 1 to 16.
- Up to 512 UTF-8 bytes per argument and 4096 bytes total. Invalid/duplicate,
  missing, fragmented, escaped, control-containing or oversized arguments are
  skipped as a whole. No matching a truncated vector against a NOT condition.
- Quoted strings and valid hex-encoded UTF-8 audit strings are supported.
- Field selectors a0 through a15, string keyword OR lists and fieldless
  `|all` keyword lists use the existing bounded wildcard interpreter. Keywords
  search the decoded, space-joined complete argv for that EXECVE record; no
  cross-record joins or arbitrary raw-event keyword searches are performed.
- SYSCALL a0 is not argv[0]. Only the numeric syslog/personality selectors are
  exposed, with explicit x86_64/i386/aarch64 syscall mappings. Raw hexadecimal
  spelling is normalized for leading zeros/case; it is not converted into an
  EXECVE string or interpreted as a pointer.

The upstream ASLR rule uses an exact personality value; combined flag values
can be collected yet still not match that exact selector. Its description does
not supply detection of every direct /proc write. Upstream command/key matches
remain heuristics, may match legitimate work and do not prove successful abuse.
The existing ignore list, cooldowns, severity settings and notification cap apply.
Retained history cannot be reanalyzed for arguments already discarded by older
versions; an accessible original raw log can be imported into separate state.

## Prepare collection without changing the host

From the checkout, as your ordinary user:

```sh
/usr/bin/python3 tools/build_sigma_profile.py
```

This writes a new `build/sigma-audit/35-skidplate-sigma.rules` and exact-removal
rollback file. It refuses root and refuses to overwrite existing drafts.
Neither the generator nor installer loads audit rules or changes host security.

The default draft watches existing regular /usr/bin executables relevant to
the rules and adds numeric syslog/personality filters for x86_64 b64/b32. Missing
or symlink executables are listed as skipped, not guessed. C2-reference tools
use the upstream `susp_activity` key. This will also match ordinary legitimate
curl/SSH and similar activity; it is not proof of a C2 connection. Additional
non-root executions may now contribute full argv to raw audit logs.

The targeted draft cannot collect every renamed/unlisted program. Miners and
shell built-ins (including some history manipulation) can evade those watches.
An explicit `--all-exec --output-dir <fresh-directory>` draft adds global exec
collection for all users, including system services. That is deliberately NOT
the default: raw audit logs can grow quickly, expose more secrets and increase
backlog pressure/lost events. Measure load, disk/rotation and auditctl lost
counters before considering broader collection. Neither mode captures every
attack, shell built-in or failed exec argument.

Before administrator activation, compare the draft with `auditctl -s` and
`auditctl -l`, existing files under /etc/audit/rules.d, available syscall names
and actual executable paths. Earlier matches can supply a different key;
overlapping rules are not a guarantee of duplicate evidence. The draft prepends
specific live rules; persistent filename 35 is intended to precede generic
rules, but existing site policy determines effective ordering. Do not use -D,
replace existing policy, ignore load errors, or change immutable/failure/backlog
settings to force installation. Exact-removal drafts require the same review:
never remove an identical rule that predated this overlay. No activation is
claimed until the live rules and safe synthetic records are checked.

## Primary implementation references

- [Sigma keyword and rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [auditctl filters, argument limits and ordering](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [Linux Audit x86_64 syscall table](https://github.com/linux-audit/audit-userspace/blob/master/lib/x86_64_table.h)
- [Linux Audit i386 syscall table](https://github.com/linux-audit/audit-userspace/blob/master/lib/i386_table.h)
- Numeric aarch64 mappings also checked against installed asm-generic/unistd.h.
