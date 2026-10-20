# Next steps: detection quality and noise control

Historical planning snapshot, saved 2026-10-19. Prototype 0.2 subsequently added
the curated Sigma backend, manual ignore management, bounded ingestion and
investigative argument context. This document records the original design goals,
not the current implementation status. See [the implementation review](REBUILD-REVIEW.md),
[argument controls](ARGUMENT-CONTEXT.md) and [current coverage](detections.md).
Any remaining proposals below require separate implementation and validation.

## Goal

Make Skidplate a useful Linux event viewer with explainable behavior detections,
process/network context and manually tunable noise reduction. Routine Firefox
AppArmor blocked-path events are the motivating example. Repetition is not proof
an event is safe. Ignoring a finding must never relax AppArmor or grant access.

## 1. Group repeated activity

- Verify and improve existing alert grouping before adding suppression.
- Show one repeated pattern with count, first seen and last seen.
- Keep distinct operations, permissions and targets distinguishable.

## 2. Review and tune alerts

- Keep Mark reviewed separate from suppression: acknowledgement alone does not
  suppress future matches.
- Retain temporary snoozes and add manually created ignore exceptions, with
  optional expiry or an explicit until-reenabled choice.
- Preview the matching conditions before saving an exception.
- Match narrowly: rule/detector context, AppArmor profile, executable, operation,
  denied permission and exact target or a deliberately selected narrow pattern.
- Explain pattern semantics and warn when an exception is broad. Avoid blanket
  Firefox suppression; different targets or permissions should remain visible
  unless explicitly covered.
- Require no changes to AppArmor, audit collection or host permissions.

## 3. Manage ignored alerts

- Add an Ignored alerts page showing matching conditions, operator reason,
  creation time, expiry, enabled status, suppressed count and latest occurrence.
- Allow editing, disabling and deleting exceptions, with an easy undo path.
- Suppression affects the main finding queue and notifications; preserve access
  to underlying events within existing retention limits.
- Surface suppression totals so a quiet queue does not imply no activity.

## 4. Add curated Sigma detections

- Start with compatible SigmaHQ Linux/auditd rules; do not import every rule.
- Evaluate an appropriate engine/backend before implementation. Chainsaw is an
  optional candidate, not a selected dependency.
- Map normalized multi-record audit events and verify field meanings, outcome
  semantics, supported operators and required collection for each rule.
- Mark rules supported, partially supported or unsupported, with clear reasons.
  Never silently enable an ineffective rule.
- The original plan discarded command arguments. A subsequent explicit design
  decision added bounded transient matching and optional saved redacted context;
  see [argument controls](ARGUMENT-CONTEXT.md) for the current privacy boundary.
- Combine single-event detections with existing behavior correlations. Assess
  correlation support explicitly; ordinary rule matching is not a sequence engine.
- Test suspicious cases and representative benign cases using synthetic or
  appropriately redacted fixtures. Tune exceptions manually; do not learn safety
  merely from frequency.
- Review rule maturity and false-positive guidance, parser/engine safety,
  resource limits, provenance, pinned versions and licenses before adoption.
- Treat rules as data; never execute commands from rule contents. No automatic
  rule downloads, host collection changes or dependency installation are agreed.

## 5. Handle overlapping detections

- For equivalent behavior on the same evidence, show one finding listing all
  matching built-in and Sigma rules, with one notification.
- Preserve distinct behaviors and linked chain evidence rather than merging
  everything from one process into one finding.
- Do not increase confidence or severity just because multiple rules match the
  same evidence; preserve each rule's rationale.
- Scope exceptions to the intended behavior so an AppArmor exception cannot
  accidentally suppress unrelated execution or network findings.
- Keep detection overlap separate from kernel audit collection overlap. Adding
  Sigma analysis must not automatically add duplicate audit rules.

## Resumption order

Review current grouping/snooze behavior, build exception management, then assess
and introduce a small tested Sigma subset. Review security implications before
running changed code, consistent with the existing project workflow.

Earlier security review follow-ups remain separate: verify actual helper
activation/sandboxing and test ingestion under pressure. These are not claims
of confirmed vulnerabilities and are not authorization to change host policy.

Reference locations (verify current contents when resuming):

- SigmaHQ Linux rules: https://github.com/SigmaHQ/sigma/tree/master/rules/linux
- Sigma log-source requirements: https://sigmahq.io/docs/basics/log-sources.html

This historical planning snapshot did not authorize publication or system changes.
