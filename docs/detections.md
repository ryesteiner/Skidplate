# Detection coverage and investigation

Prototype 0.2 defaults to the bundled SigmaHQ subset. The table below also
describes retained prototype algorithms; not all are default alerts now. See
[the rebuild coverage and backend limits](REBUILD-REVIEW.md) and the in-app
Sigma catalog for actual supported/inactive rules and local supplements.

Detectors operate on captured audit evidence. They do not install audit policy,
inspect arbitrary file contents, authenticate executable products or prove an
attack. High is review priority; Medium often includes legitimate administration.

| Area | Signals | Important limits |
|---|---|---|
| Authentication | Failure bursts; success after matching failures; sudo PAM/account and command-authorization outcomes | Requires userspace audit logging; authorization does not prove a command ran |
| Privilege | Privilege-tool exec; supported root-UID requests; observed exec transition; risky root exec; process-memory writes; BPF program load | Requires captured syscall/exec evidence; saved-ID restoration/debugging can match |
| Persistence | systemd, cron/at, shell profiles, XDG autostart, SSH keys/rc, loader, udev, pacman hooks; ordered execution/persistence/network chains | Captured operation/location, not content or authorization; custom paths and missing watches are gaps |
| Enumeration | nmap/masscan/zmap basename; outgoing multi-port/multi-host connect patterns | No incoming or raw-packet scan detection; legitimate tools/discovery can match |
| Remote access | Selected SSH/VNC/RustDesk/AnyDesk executable names; supported SSH login/session records | Names do not establish product identity; no complete remote-session tracking |
| Network | Explicit IP/CIDR watchlist; temporary executables connecting; persistence/connect chain; periodic attempts | No arbitrary C2 verdict, packet/DNS beacon analysis or persistent-socket behavior |
| System policy | Identity, sudo/PAM, audit, MAC, kernel, boot/network/package configuration and denied accesses | Depends on watch keys; opens/metadata do not prove content changes; blocked is not compromised |
| DNS | Configuration tampering and selected systemd-resolved DNSSEC journal events | Not general forged-DNS-packet detection |

## Correlation thresholds

- Authentication defaults: 5 USER_AUTH failures per host/account/address in 300s.
- Root exec transition: same host/login/session/PID within 120s; different
  executable images are compared. No process-start token is available.
- Persistence/network and risky execution chains: within 300s, same validated
  host/non-system login/session/PID/executable. Exec/daemon/source resets apply.
- Port sweep: 20 unique ports on one address within 60s (loopback is Medium).
- Host sweep: 30 addresses on one port in 60s plus scanner basename or at least
  80% selected failed attempts. Authorized scans/network failures can match.
- Periodic attempts: 12 public-IP connects to one endpoint; median interval
  10–120s, each gap within 20%, span at least 120s. Medium; normal polling matches.

Failed or EINPROGRESS connect records do not establish a connection. Correlation
is bounded and transient; hosts/live/history stay separate. PID reuse, missing
execs, clock changes and caps limit conclusions. Numeric syscall support covers
selected x86_64, i386 and aarch64 ABIs, not all Linux syscall formats/mechanisms.

## Evidence and noise

Select a finding to see operation/result, captured target roles, saved identities,
first/latest linked examples and bounded nearby host activity. Nearby means
potentially unrelated; a systemd or package event at the same time does not prove
attribution. Current socket inspection is a separate snapshot. A captured loader
path during execve is not a write to that loader.

Cyan users, amber paths, violet endpoints, bold IDs and green/rose results are
field cues, not verdicts. Full plain text stays selectable/copyable. Mark reviewed
when investigated; snooze matching context for 10m/1h/24h to reduce repeated
popups while retaining findings. Disabled rules create no alerts. Default
High/focused notifications leave Medium findings available in All alerts/Behavior.

Learning lasts 24h from first live root exec (or manual extension), stores up to
2048 executable paths and only flags new paths afterward. It is not an integrity
baseline or proof a program is safe. Historical imports never train it.
