# Investigative command arguments: saved data, never runnable actions

Matching alerts can now include **SAVED COMMAND ARGUMENTS / DATA ONLY**. It shows
the captured argv by index, separately from the audit executable identity, with
best-effort redaction and a 4096-character display budget. Sigma findings also
name the selections and argument fields that matched; these names come from
the rule, not from log-supplied code. Selection names describe matching evidence,
not proof that a command succeeded or an attack occurred.

This context is enabled by default for the requested investigative workflow.
In Settings, disable **Save redacted command arguments with matching alerts**
to return to no-argument persistence for future findings. Turning it off does
not purge existing saved context. Existing private-state permissions and normal
seven-day/2000-alert-group retention apply. Saved summaries still exclude argv;
context appears only in the matching alert details, not every execution record.
Different argument contexts can now create separate local alert groups/precise
exceptions. Existing notification caps and manual noise controls still apply.
An ignore exception's descriptive text can copy part of the alert, including
redacted argument context, and can retain it after the alert expires. Edit or
delete that exception to remove its copied description; expiry/disable alone
does not erase the saved exception.

## Protections against unintended execution

- Each value is displayed separately as JSON-escaped text; a complete shell
  command line is never reconstructed.
- Shell metacharacters including dollar signs, backticks, separators, redirects
  and parentheses are additionally rendered with JSON Unicode escapes. Newlines,
  controls and bidi characters are visible escapes, not layout/terminal controls.
- The evidence widget uses plain GTK text, not markup, links or executable code.
  There is no run, open-path, URL-launch, decode-and-run or copy-as-command action.
- The existing Copy button copies evidence text only. No argument reaches a
  subprocess, shell, privileged helper, file reader, process inspection command,
  browser, desktop notification or diagnostic message.

Viewing/copying in Skidplate does not execute evidence. Manually pasting evidence
into a terminal or another interpreter is outside that boundary and can still
be dangerous. Do not treat the display or redaction as a safe shell format.
Argument zero is caller-supplied text, not verified application identity.

## Privacy and limits

Known password/token/API-key/credential options and assignments, common auth
headers, inline script/eval values, request bodies and token-like values are
masked. URL credentials and path/query/fragment details are hidden while a
simple destination authority is retained. Ordinary flags and file paths may
remain visible; paths themselves can be private. File-upload options show the
captured filename, never the file's contents. Application journal messages still
remain transient and are never saved by this feature.

**Redaction is best effort. Unknown secret names, formats and positional values
can remain in saved context.** Private history, backups, screenshots and copied
evidence must be treated as potentially sensitive. Disable the feature if that
tradeoff is unacceptable. Raw audit/journal logs and transient matcher memory
remain separate sources of exposure; Python does not guarantee zeroization.
A normal sudo prompt password is not argv and is not collected by this view.

Context uses only the already captured complete single-record EXECVE vector:
at most 16 arguments, 512 bytes each and 4096 bytes total. Missing, split,
invalid or oversized argv yields no saved argument view; no /proc command line,
environment, memory, terminal input or evidence-selected files are read to fill
gaps. The redacted view can omit later arguments when its display budget is
reached. Original detection still uses the bounded transient argument data;
redaction does not weaken or change the rule selector.

This does not recover arguments from old saved summaries or from a later
connect/file-change event with no captured EXECVE. For an accessible original
raw audit log, a separate-state import can analyze records again; avoid mixing
historical evidence into live state unintentionally.

Tests cover representative credential formats, URL/body/code masking, shell
payloads remaining data, display bounds, private alert persistence versus
summary exclusion, disabling persistence, and precise local exceptions.

Validation: the implementation and pre-execution URL/compact-option corrections
were reviewed with Codex Security. The final suite ran 148 tests successfully,
with one display-dependent test skipped. Native GUI/clipboard integration was
not exercised in this session. Unknown-format redaction is not guaranteed.
