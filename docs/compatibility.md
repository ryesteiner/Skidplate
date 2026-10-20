# Naming and compatibility

The project/product is **Skidplate**, source module `skidplate`, command
`skidplate`, desktop entry `skidplate.desktop`, service `skidplate.service` and
tray ID `skidplate`. Fresh state is `skidplate/skidplate.sqlite3` under the XDG
state home. The optional helper uses `org.skidplate.LogAccess1` and
`skidplate-log-access.service`.

Two legacy names are intentionally accepted to preserve existing history:

- If only `<state-home>/audit-sentinel` exists, the default state selector uses
  it without moving or copying anything. If both legacy/current directories
  exist, choose explicitly with `--state-dir`; the app will not guess/merge.
- Within a selected private directory, an existing `sentinel.sqlite3` is reused.
  Fresh databases use `skidplate.sqlite3`. Both files existing is an error.

The shared `app.lock` prevents the old/new app running on the same state at
once. Stop the older service before starting the new one. No compatibility
module alias is shipped; update Python imports to `skidplate`.

Audit keys such as `sentinel_connect` and `sentinel_persistence` are an existing
collection-data interface, not product branding. They deliberately remain
recognized and emitted by draft generators, so existing kernel rules, saved
history, alert fingerprints and snoozes do not need a global rewrite. Existing
Omarchy/reference keys are also recognized. Do not rename live audit keys or
reset rules merely to match the product name.

Generated rule filenames now use `40-skidplate-dns`, `60-skidplate` and
`70-skidplate-persistence`. These are not automatically installed. If you
already deployed the older filenames, compare/merge rather than installing
duplicate equivalent profiles. The old working checkout is not modified by
preparing this clean repository.
