"""Bounded raw-audit parsing, deterministic detections, and private local storage.

No subprocesses, network clients, privilege elevation, or source-file writes.
Audit records and their fields are untrusted data, never commands or markup.
"""
from __future__ import annotations

import collections
import dataclasses
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from .behavior import BehaviorCorrelator, number, process_identity
from .persistence import changes as persistence_changes, PERSISTENCE_RULES
from .signals import Chokepoints, UID_CALLS, RULES as CHOKEPOINT_RULES, direct as direct_signals
from .evidence import operation as describe_operation, targets as captured_targets
from .paths import database_path
from .argument_context import describe_arguments

MAX_LINE = 65536
MAX_RECORDS = 32
MAX_PENDING = 128
MAX_EVENTS = 5000
MAX_ALERTS = 2000
MAX_BASELINE = 2048
# Preserve direct high-risk evidence while upstream coverage is intentionally
# limited. Broad prototype watch-key signatures stay retired by default.
LOCAL_SUPPLEMENTS = frozenset({'audit-health', 'audit-config', 'policy-denial', 'auth-burst',
    'network-watchlist', 'dnssec-validation', 'dnssec-downgrade', 'dnssec-trust-anchor',
    'root-temp-exec', 'root-user-exec', 'memory-exec', 'process-injection', 'bpf-program-load',
    'network-temp-exec'})
HEADER = re.compile(r"\btype=([A-Z0-9_]+)\s+msg=audit\((\d{1,12}(?:\.\d{1,6})?):(\d{1,20})\):\s?(.*)")
FIELD_KEY = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
FIELD_VALUE = re.compile(r'''"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s]+''')
EXEC_CALLS = {"c000003e": {"59", "322"}, "40000003": {"11", "358"},
              "c00000b7": {"221", "281"}}
CONNECT_CALLS = {"c000003e": {"42"}, "40000003": {"362"}, "c00000b7": {"203"}}
ARGUMENT_CLASSES = {"c000003e": {"101": "ptrace_request", "321": "bpf_command"},
                    "40000003": {"26": "ptrace_request", "357": "bpf_command"},
                    "c00000b7": {"117": "ptrace_request", "280": "bpf_command"}}
MEMORY_WRITE_CALLS = {"c000003e": "311", "40000003": "348", "c00000b7": "271"}
# Collection keys describe evidence, never prove malicious intent. Recognize
# both the existing Omarchy keys and the reference's equivalent categories.
KEY_SIGNALS = (
    ({"identity_changes", "etcpasswd", "etcgroup"}, "identity-change", "high", "Identity database changed"),
    ({"sudo_changes", "actions", "pam", "login", "sentinel_auth_policy"}, "privilege-policy", "high", "Authentication or privilege policy changed"),
    ({"systemd_persistence", "systemd", "cron", "init", "udev", "shell_profiles", "sentinel_persistence"}, "persistence-change", "high", "Persistence configuration changed"),
    ({"kernel_modules", "modules", "modprobe", "sysctl", "KEXEC", "sentinel_kernel_config"}, "kernel-change", "high", "Kernel code or configuration changed"),
    ({"auditconfig", "audispconfig", "sentinel_audit_config"}, "audit-tamper", "high", "Audit collection configuration changed"),
    ({"mac_policy", "sentinel_mac_policy"}, "security-policy-change", "high", "Mandatory security policy changed"),
    ({"network_modifications", "firewall", "sentinel_network_config"}, "network-policy-change", "high", "Network or firewall configuration changed"),
    ({"sentinel_dns_config"}, "dns-config-change", "high", "DNS-related configuration changed"),
    ({"bin_writes", "usr_writes", "boot_writes", "libpath", "systemwide_preloads", "sentinel_system_files"}, "system-file-change", "high", "System executable, loader or boot path activity"),
    ({"software_mgmt", "sentinel_pacman_config"}, "package-config", "medium", "Package manager configuration changed"),
    ({"sentinel_config_change"}, "configuration-change", "medium", "Other system configuration changed"),
    ({"sentinel_pacman_exec"}, "package-manager", "medium", "Pacman was executed"),
    ({"sentinel_privilege_tool"}, "privilege-tool", "medium", "Privilege administration tool was executed"),
    ({"unauthedfileaccess", "unauthedfileaccess_system", "file_access", "sentinel_access_denied"}, "access-denied", "medium", "File access was denied"),
    ({"perm_mod", "sentinel_perm_change"}, "permission-change", "medium", "File permissions or ownership changed"),
    ({"T1070_006_timestomp", "sentinel_time_change"}, "timestamp-change", "medium", "File timestamps were modified"),
    ({"anon_file_create", "bpf", "namespaces", "process_vm", "tracing", "io_uring", "userfaultfd", "af_alg", "raw_network_socket_created", "socket_bpf_filter_attached", "sentinel_kernel_surface"}, "kernel-surface", "medium", "Security-relevant kernel interface used"),
    ({"mount", "swap", "sentinel_mount"}, "mount-change", "medium", "Mount or namespace configuration used"),
)
POLICY_FIELDS = {"apparmor", "operation", "profile", "name", "requested_mask",
                 "denied_mask", "family", "sock_type", "protocol", "capname",
                 "scontext", "tcontext", "tclass", "permissive"}
TYPE_NAMES = {"1100": "USER_AUTH", "1107": "USER_AVC", "1112": "USER_LOGIN",
              "1101": "USER_ACCT", "1105": "USER_START", "1106": "USER_END", "1123": "USER_CMD",
              "1130": "SERVICE_START", "1131": "SERVICE_STOP",
              "1200": "DAEMON_START", "1201": "DAEMON_END", "1202": "DAEMON_ABORT",
              "1203": "DAEMON_CONFIG", "1300": "SYSCALL", "1305": "CONFIG_CHANGE",
              "1306": "SOCKADDR", "1309": "EXECVE", "1320": "EOE",
              "1326": "SECCOMP", "1400": "AVC"}
KEPT_FIELDS = {"uid", "euid", "auid", "pid", "ppid", "ses", "res", "success", "acct", "addr",
               "exe", "key", "arch", "syscall", "op", "audit_enabled", "enabled",
               "saddr", "exit", "ptrace_request", "bpf_command", "nametype", "cwd",
               "requested_euid", "uid_operation", "unit", "comm"} | POLICY_FIELDS


def dns_configuration_target(event):
    paths = {"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf"}
    rows = [row for row in event.records if row.kind == "PATH"]
    for row in rows:
        if row.values.get("name") in paths:
            return row.values["name"]
    # Some rename/unlink events carry a parent directory and a basename.
    if any(row.values.get("name") == "/etc" and row.values.get("nametype") == "PARENT" for row in rows):
        for row in rows:
            candidate = "/etc/" + row.values.get("name", "")
            if candidate in paths and row.values.get("nametype") != "PARENT":
                return candidate
    return ""


def clean(value: object, limit: int = 512) -> str:
    """Keep UI/log text plain and strip controls and bidi direction overrides."""
    return "".join(c for c in str(value)[:limit]
                   if c.isprintable() and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def field_tokens(text: str):
    """Linear scan shared by ordinary fields and strict transient argv parsing."""
    position = 0
    while position < len(text):
        match = FIELD_KEY.match(text, position)
        if match is None:
            position += 1
            continue
        key = match.group()
        position = match.end()
        # Consume a whole identifier even without '='. An unanchored search
        # retries every suffix of a long bare identifier, causing quadratic work.
        if position == len(text) or text[position] != "=":
            continue
        position += 1
        match = FIELD_VALUE.match(text, position)
        if match is None:
            continue
        value = match.group()
        position = match.end()
        quoted = len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]
        if quoted:
            value = value[1:-1]
        yield key, value, quoted


def fields(text: str, depth: int = 0) -> dict[str, str]:
    result = {}
    for key, value, quoted in field_tokens(text):
        # Fields within the audit userspace msg payload are needed for res/acct.
        if key == "msg" and depth == 0:
            # Do not let an operational payload override kernel subject IDs.
            for inner, content in fields(value, 1).items():
                if inner in {"res", "acct", "addr", "op", "terminal", "hostname", "exe"}:
                    result.setdefault(inner, content)
        else:
            if not quoted and key in {"exe", "acct", "comm", "key", "name", "cwd"} and re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", value):
                value = bytes.fromhex(value).decode("utf-8", errors="replace")
            result.setdefault(key, value)
    return result


def transient_exec_arguments(body):
    """Only complete, small, single-record argv; never persisted or executed.

    Kernel EXECVE encodes unsafe strings as hex. Truncation, split arguments,
    duplicate fields and invalid encoding reject the whole argument view. This
    avoids evaluating negative keyword conditions against incomplete argv.
    """
    if re.search(r'\ba[0-9]+\[', body):
        return {}
    tokens = [(key, value, quoted) for key, value, quoted in field_tokens(body)
              if key == 'argc' or re.fullmatch(r'a[0-9]+(?:_len)?', key)]
    if len(tokens) > 17 or len({key for key, _, _ in tokens}) != len(tokens):
        return {}
    argc = next((value for key, value, _ in tokens if key == 'argc'), '')
    if not re.fullmatch(r'[0-9]{1,2}', argc) or not 1 <= int(argc) <= 16:
        return {}
    expected = {'argc'} | {f'a{i}' for i in range(int(argc))}
    if {key for key, _, _ in tokens} != expected:
        return {}
    arguments = {}
    total = 0
    for key, value, quoted in tokens:
        if key == 'argc':
            continue
        if not quoted:
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,512}', value):
                return {}
            try:
                value = bytes.fromhex(value).decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                return {}
        if len(value.encode('utf-8')) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value) or '\\' in value:
            return {}
        total += len(value.encode('utf-8'))
        if total > 4096:
            return {}
        arguments[key] = value
    return arguments


@dataclasses.dataclass
class Record:
    kind: str
    timestamp: float
    serial: str
    values: dict[str, str]
    node: str = "local"
    context_digest: str = ""
    # Separate from retained fields: bounded secrets may exist briefly in RAM.
    # No summary, UI evidence or diagnostic formatter serializes this mapping.
    sigma_arguments: dict[str, str] = dataclasses.field(default_factory=dict, repr=False)
    application_message: str = dataclasses.field(default='', repr=False)

    @property
    def identity(self) -> str:
        return f"{self.node}:{self.timestamp:.6f}:{self.serial}"


def parse_line(line: str) -> Record | None:
    if len(line) > MAX_LINE:
        raise ValueError("Oversized audit record skipped")
    # ENRICHED logs append interpreted fields after the audit separator. Preserve
    # authoritative raw fields rather than allowing enrichment to replace them.
    line = line.split("\x1d", 1)[0]
    match = HEADER.search(line)
    if not match:
        return None
    kind, timestamp, serial, body = match.groups()
    if len(kind) > 64:
        raise ValueError("Invalid audit record type")
    node = fields(line[:match.start()]).get("node", "local")
    values = fields(body)
    normalized_kind = TYPE_NAMES.get(kind, kind)
    sigma_arguments = transient_exec_arguments(body) if normalized_kind == 'EXECVE' else {}
    # Syscall a0 is a raw hexadecimal numeric argument, NOT EXECVE argv[0].
    # Only expose the two verified syscall selectors; never pointer arguments.
    numeric_calls = {'c000003e': {'103', '135'}, '40000003': {'103', '136'},
                     'c00000b7': {'116', '92'}}
    if normalized_kind == 'SYSCALL' and values.get('syscall') in numeric_calls.get(values.get('arch', '').lower(), set()):
        raw_a0 = values.get('a0', '')
        if re.fullmatch(r'[0-9a-fA-F]{1,16}', raw_a0):
            sigma_arguments = {'a0': format(int(raw_a0, 16), 'x')}
    # Decode only the fixed numeric operation selector needed by these rules;
    # discard raw syscall arguments as before. Do not accept injected classes.
    values.pop("ptrace_request", None)
    values.pop("bpf_command", None)
    values.pop("requested_euid", None)
    values.pop("uid_operation", None)
    if TYPE_NAMES.get(kind, kind) == "SYSCALL":
        selector = ARGUMENT_CLASSES.get(values.get("arch", "").lower(), {}).get(values.get("syscall"))
        raw = values.get("a0", "")
        if selector and re.fullmatch(r"[0-9a-fA-F]{1,16}", raw):
            values[selector] = str(int(raw, 16))
        uid_call = UID_CALLS.get(values.get('arch', '').lower(), {}).get(values.get('syscall'))
        if uid_call:
            raw_uid = values.get(uid_call[1], '')
            if re.fullmatch(r'[0-9a-fA-F]{1,16}', raw_uid) and int(raw_uid, 16) <= 4294967295:
                values['requested_euid'] = str(int(raw_uid, 16))
                values['uid_operation'] = uid_call[0]
    # Hash full stable fields before display/storage truncation. PIDs and event
    # IDs vary between repetitions; never use cleaned UI text as a mute key.
    context = {key: value for key, value in values.items()
               if key in KEPT_FIELDS and key not in {"pid", "ppid", "ses"}}
    if sigma_arguments:
        # Distinguish exact exceptions without saving argv. A hash is neither
        # encryption nor protection against guessing low-entropy arguments.
        context['sigma_argument_digest'] = hashlib.sha256(json.dumps(sigma_arguments, sort_keys=True).encode()).hexdigest()
    if kind in {"AVC", "1400", "USER_AVC", "1107", "SELINUX_ERR", "SECCOMP", "1326"}:
        # AppArmor exposes operation/profile/target as fields. For other policy
        # formats retain exactness rather than guessing at missing permissions.
        if values.get("apparmor"):
            context["policy_fields"] = {key: value for key, value in values.items()
                                        if key not in {"pid", "ppid", "ses"}}
        else:
            context["policy_record"] = body
    digest = hashlib.sha256(json.dumps([node, context], sort_keys=True).encode()).hexdigest()
    values = {key: value[:4096 if key in {"exe", "name", "cwd"} else 256]
              for key, value in values.items() if key in KEPT_FIELDS}
    return Record(normalized_kind, float(timestamp), serial, values, clean(node, 128), digest, sigma_arguments)


def network_watchlist(text: str):
    """Explicit destination IPs/CIDRs, with bounded work and no DNS lookups."""
    if len(text) > 8192:
        raise ValueError("Destination watchlist is too long")
    entries = text.replace(",", " ").split()
    if len(entries) > 64:
        raise ValueError("Use at most 64 destination IPs or CIDRs")
    return tuple(ipaddress.ip_network(entry, strict=False) for entry in entries)


def network_destinations(event):
    # Supported audit architectures here are little-endian Linux. The port and
    # IP bytes use network byte order; IPv6 address starts after flowinfo.
    if event.get("arch").lower() not in CONNECT_CALLS:
        return []
    destinations = []
    for row in event.records:
        raw = row.values.get("saddr", "")
        if row.kind != "SOCKADDR" or not re.fullmatch(r"[0-9a-fA-F]{16,56}", raw):
            continue
        try:
            data = bytes.fromhex(raw)
            family = int.from_bytes(data[:2], "little")
            if family == 2 and len(data) == 16:
                address = ipaddress.ip_address(data[4:8])
            elif family == 10 and len(data) == 28:
                address = ipaddress.ip_address(data[8:24])
            else:
                continue
            destinations.append((address, int.from_bytes(data[2:4], "big")))
        except ValueError:
            continue
    return destinations


@dataclasses.dataclass
class Event:
    records: list[Record]

    @property
    def identity(self):
        return self.records[0].identity

    @property
    def timestamp(self):
        return self.records[0].timestamp

    @property
    def kinds(self):
        return {r.kind for r in self.records}

    def get(self, key, default=""):
        # SYSCALL is authoritative for subject identity and executable when an
        # event also contains PATH/EXECVE records with similarly named fields.
        ordered = sorted(self.records, key=lambda r: r.kind != "SYSCALL")
        return next((r.values[key] for r in ordered if key in r.values), default)

    @property
    def result(self):
        syscall = next((r for r in self.records if r.kind == "SYSCALL"), None)
        if syscall and "success" in syscall.values:
            return syscall.values["success"]
        return self.get("res", self.get("success"))

    def summary(self):
        # Intentionally exclude raw records, EXECVE arguments, proctitle, cwd,
        # and PATH records. Those often contain sensitive command-line data.
        return {"types": ", ".join(sorted(self.kinds - {"EOE"})),
                "auid": clean(self.get("auid"), 32), "uid": clean(self.get("uid"), 32),
                "exe": clean(self.get("exe")), "account": clean(self.get("acct"), 128),
                "address": clean(self.get("addr"), 128),
                "result": clean(self.result, 32),
                "key": clean(self.get("key"), 128),
                "pid": clean(self.get("pid"), 32), "ppid": clean(self.get("ppid"), 32),
                "euid": clean(self.get("euid"), 32), "session": clean(self.get("ses"), 32),
                "node": clean(self.records[0].node, 128),
                "policy": {key: clean(self.get(key), 512) for key in ('profile', 'operation', 'denied_mask', 'name')},
                "operation": clean(describe_operation(self), 256),
                "exit": clean(self.get('exit'), 32),
                "unit": clean(self.get('unit'), 256) if self.kinds & {'SERVICE_START', 'SERVICE_STOP', 'APPLICATION_LOG'} else '',
                "application": {'product': clean(self.get('application_product'), 32), 'scope': clean(self.get('source_scope'), 16)}
                    if 'APPLICATION_LOG' in self.kinds else {},
                "targets": [{"path": clean(item['path'], 512), "kind": clean(item['kind'], 32)} for item in captured_targets(self)],
                "persistence": [{"rule": item.rule, "target": clean(item.target, 512), "operation": item.operation}
                                for item in persistence_changes(self)],
                "connections": [{"ip": str(ip), "port": port} for ip, port in network_destinations(self)]
                    if ("SYSCALL" in self.kinds and self.get("syscall") in
                        CONNECT_CALLS.get(self.get("arch").lower(), set())) else []}


class Assembler:
    def __init__(self):
        self.pending = collections.OrderedDict()
        self.dropped = 0

    def feed(self, record: Record, now=None) -> list[Event]:
        now = time.monotonic() if now is None else now
        complete = []
        if record.identity not in self.pending and len(self.pending) >= MAX_PENDING:
            _, (rows, _) = self.pending.popitem(last=False)
            complete.append(Event(rows))
            self.dropped += 1  # Early flush: surface pressure, never silently claim full coverage.
        rows, _ = self.pending.get(record.identity, ([], now))
        if len(rows) < MAX_RECORDS:
            rows.append(record)
        else:
            self.dropped += 1
        self.pending[record.identity] = (rows, now)
        if record.kind == "EOE":
            complete.append(Event(self.pending.pop(record.identity)[0]))
        return complete

    def flush(self, now=None, force=False):
        now = time.monotonic() if now is None else now
        complete = []
        for key, (rows, updated) in list(self.pending.items()):
            if force or now - updated >= 1.5:
                complete.append(Event(rows))
                del self.pending[key]
        return complete


class LogFollower:
    """Read a regular file, follow rename/create and copy-truncate rotation.

    First open reads a bounded recent tail. A new rotated file starts at byte 0.
    No log access is requested or elevated by this class.
    """
    def __init__(self, path: Path, tail_bytes=2 * 1024 * 1024):
        self.path = Path(path)
        self.tail_bytes = tail_bytes
        self.fd = None
        self.identity = None
        self.buffer = b""
        self.discard = False
        self.opened_once = False
        self.recent_history = False
        self.status = "Not connected"
        self.skipped = 0
        self.rotations = 0
        self.access_lost = False
        self.resume_position = 0

    def close(self):
        if self.fd is not None:
            try:
                self.resume_position = os.lseek(self.fd, 0, os.SEEK_CUR)
            except OSError:
                pass
            os.close(self.fd)
        self.fd = None

    def _open(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise ValueError("Log source must be a regular file, not a pipe/device")
        same_file = self.identity == (info.st_dev, info.st_ino)
        self.fd, self.identity = fd, (info.st_dev, info.st_ino)
        if self.opened_once and same_file:
            os.lseek(fd, self.resume_position if info.st_size >= self.resume_position else 0, os.SEEK_SET)
        elif not self.opened_once and info.st_size > self.tail_bytes:
            os.lseek(fd, info.st_size - self.tail_bytes, os.SEEK_SET)
            self.discard = True
            self.recent_history = True
        self.opened_once = True

    def poll(self, budget=256 * 1024) -> list[str]:
        try:
            if self.fd is None:
                self._open()
            current = self.path.stat(follow_symlinks=False)
            if not stat.S_ISREG(current.st_mode):
                raise ValueError("Log source changed to a non-regular file")
            if (current.st_dev, current.st_ino) != self.identity:
                # Drain the old open inode before switching, within the same
                # per-tick budget. A gap can still occur while the app is stopped.
                data = os.read(self.fd, budget)
                if data:
                    return self._lines(data)
                self.close()
                if self.buffer:
                    self.skipped += 1
                self.buffer = b""
                self.discard = False
                self.rotations += 1
                self._open()
            elif current.st_size < os.lseek(self.fd, 0, os.SEEK_CUR):
                os.lseek(self.fd, 0, os.SEEK_SET)
                if self.buffer:
                    self.skipped += 1
                self.buffer = b""
                self.discard = False
                self.rotations += 1
            data = os.read(self.fd, budget)
            self.access_lost = False
            self.status = "Source readable · auditd health/rule coverage not verified"
            return self._lines(data)
        except (OSError, ValueError) as exc:
            self.close()
            self.buffer = b""
            self.discard = False
            self.access_lost = isinstance(exc, PermissionError)
            reason = "Log access lost · " if self.access_lost else ""
            self.status = f"MONITORING UNAVAILABLE · {reason}{clean(exc)}"
            return []

    def _lines(self, data):
        combined = self.buffer + data
        pieces = combined.split(b"\n")
        self.buffer = pieces.pop()
        output = []
        for piece in pieces:
            if self.discard:
                self.discard = False
                continue
            if len(piece) > MAX_LINE:
                self.skipped += 1
            else:
                output.append(piece.decode("utf-8", errors="replace"))
        if len(self.buffer) > MAX_LINE:
            self.buffer = b""
            self.discard = True
            self.skipped += 1
        return output


class Store:
    def __init__(self, directory: Path):
        self.batching = False
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("State directory must be an owned, private (0700), non-symlink directory")
        db = database_path(directory)
        try:
            fd = os.open(db, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
        info = db.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise PermissionError("Database must be an owned, private regular file")
        self.db = sqlite3.connect(db)
        self.db.executescript("""
          PRAGMA journal_mode=DELETE;
          PRAGMA secure_delete=ON;
          PRAGMA max_page_count=16384;
          CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, ts REAL, data TEXT);
          CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, rule TEXT,
            severity TEXT, title TEXT, detail TEXT, acknowledged INTEGER DEFAULT 0);
          CREATE TABLE IF NOT EXISTS baseline(exe TEXT PRIMARY KEY);
          CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
          CREATE TABLE IF NOT EXISTS snoozes(fingerprint TEXT PRIMARY KEY, until REAL);
          CREATE INDEX IF NOT EXISTS event_time ON events(ts);
          CREATE INDEX IF NOT EXISTS alert_time ON alerts(ts);
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(alerts)")}
        if "fingerprint" not in columns:
            self.db.execute("ALTER TABLE alerts ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
        additions = {"occurrences": "INTEGER NOT NULL DEFAULT 1", "first_ts": "REAL",
                     "first_event": "TEXT NOT NULL DEFAULT ''", "last_event": "TEXT NOT NULL DEFAULT ''",
                     "historical": "INTEGER NOT NULL DEFAULT 0"}
        for column, declaration in additions.items():
            if column not in columns:
                self.db.execute(f"ALTER TABLE alerts ADD COLUMN {column} {declaration}")
        self.db.execute("UPDATE alerts SET historical=1 WHERE first_ts IS NULL AND detail LIKE 'Historical finding;%'")
        self.db.execute("UPDATE alerts SET first_ts=ts WHERE first_ts IS NULL")
        self.db.execute("CREATE INDEX IF NOT EXISTS alert_group ON alerts(fingerprint,rule,historical,ts)")
        # Bootstrap only from history still present. Old purged events cannot be recovered.
        self.db.execute("INSERT OR IGNORE INTO meta VALUES('events_processed', (SELECT COUNT(*) FROM events))")
        self.db.execute("INSERT OR IGNORE INTO meta VALUES('counter_started', ?)", (str(time.time()),))
        self.db.commit()

    def get(self, key, default=""):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def commit(self):
        """The GUI can commit a short ingestion batch instead of every event."""
        if not self.batching:
            self.db.commit()

    def set(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, str(value)))
        self.db.commit()

    def event(self, event):
        cursor = self.db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?)",
                                 (event.identity, event.timestamp, json.dumps(event.summary())))
        if cursor.rowcount:
            # Same transaction as event insertion: rollback/retry cannot inflate the counter.
            self.db.execute("UPDATE meta SET value=min(CAST(value AS INTEGER)+1,9000000000000000) "
                            "WHERE key='events_processed'")
        return bool(cursor.rowcount)

    def related(self, field, value):
        """Structured exact-match pivot over all retained summaries, not a text search."""
        if field not in {'pid', 'ppid', 'exe', 'auid', 'session', 'node'} or not value:
            return []
        rows = []
        for identity, timestamp, data in self.rows(limit=MAX_EVENTS):
            summary = json.loads(data)
            if summary.get(field) == value:
                rows.append((identity, timestamp, summary))
                if len(rows) >= 200:
                    break
        return rows

    def alert(self, rule, severity, title, detail, now, fingerprint="", event_id="", first_event="", historical=False):
        row = self.db.execute("SELECT id FROM alerts WHERE fingerprint=? AND rule=? AND severity=? "
            "AND historical=? AND first_ts>=? AND ts<=? ORDER BY ts DESC LIMIT 1",
            (fingerprint, rule, severity, int(historical), now - 3600, now)).fetchone() if fingerprint else None
        if row:
            self.db.execute("UPDATE alerts SET ts=?,detail=?,last_event=?,occurrences=min(occurrences+1,1000000000),"
                "acknowledged=0 WHERE id=?", (now, detail, event_id, row[0]))
            return row[0]
        cursor = self.db.execute("INSERT INTO alerts(ts,rule,severity,title,detail,fingerprint,first_ts,first_event,last_event,historical) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)", (now, rule, severity, title, detail, fingerprint, now,
                                           first_event or event_id, event_id, int(historical)))
        return cursor.lastrowid

    def alert_stats(self):
        return {row[0]: row[1:] for row in self.db.execute(
            "SELECT id,occurrences,first_ts,first_event,last_event,historical FROM alerts")}

    def investigation(self, alert_id):
        row = self.db.execute("SELECT first_event,last_event FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            return [], 'No saved alert.'
        seeds = []
        for identity in dict.fromkeys(row):
            saved = self.db.execute("SELECT id,ts,data FROM events WHERE id=?", (identity,)).fetchone()
            if saved:
                seeds.append((saved[0], saved[1], json.loads(saved[2])))
        if not seeds:
            return [], 'Linked event summaries are unavailable (older version or retention limit).'
        anchor = seeds[-1][2]
        required = ('node', 'auid', 'session', 'pid', 'exe')
        if (not all(anchor.get(key) for key in required) or
                not number(anchor.get('pid', ''), 1) or not number(anchor.get('auid', ''), 1000) or
                not number(anchor.get('session', '')) or
                not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', anchor.get('node', ''))):
            return seeds, 'Linked events only: process/session metadata is incomplete.'
        results = {entry[0]: entry for entry in seeds}
        # Bound both the time range and number of candidate summaries inspected.
        for identity, timestamp, data in self.db.execute(
            "SELECT id,ts,data FROM events WHERE ts BETWEEN ? AND ? ORDER BY ts DESC LIMIT 200",
            (seeds[-1][1] - 300, seeds[-1][1] + 60)):
            summary = json.loads(data)
            if all(summary.get(key) == anchor[key] for key in required):
                results[identity] = identity, timestamp, summary
        seed_ids = {entry[0] for entry in seeds}
        nearby = sorted((entry for identity, entry in results.items() if identity not in seed_ids),
                        key=lambda entry: entry[1])[-(50 - len(seeds)):]
        return sorted(seeds + nearby, key=lambda entry: entry[1]), (
            'First/latest linked examples plus nearby summaries matching host, login UID, session, PID and executable. '
            'Maximum 200 candidates / 50 results; these are context, not proof of causation or a complete process tree.')

    def nearby_context(self, alert_id):
        """Host/time context only, explicitly separate from strict process links."""
        linked = self.db.execute('SELECT last_event FROM alerts WHERE id=?', (alert_id,)).fetchone()
        anchor = self.db.execute('SELECT ts,data FROM events WHERE id=?', (linked[0],)).fetchone() if linked else None
        if not anchor:
            return [], 'No retained anchor event; nearby context unavailable.'
        timestamp, data = anchor[0], json.loads(anchor[1])
        rows = []
        for identity, when, raw in self.db.execute(
                'SELECT id,ts,data FROM events WHERE ts BETWEEN ? AND ? ORDER BY ABS(ts-?),ts,id LIMIT 100',
                (timestamp - 60, timestamp + 60, timestamp)):
            summary = json.loads(raw)
            if identity != linked[0] and data.get('node') and summary.get('node') == data['node']:
                rows.append((identity, when, summary))
                if len(rows) == 20:
                    break
        return sorted(rows, key=lambda row: row[1]), (
            'Same-host summaries within ±60s; up to 100 candidates / 20 results. '
            'Temporal context only: these may be unrelated processes, services or package operations. '
            'No missing journal/package history is inferred. Retention and collection gaps apply.')

    def active_snoozes(self, now=None):
        now = time.time() if now is None else now
        return dict(self.db.execute("SELECT fingerprint,until FROM snoozes WHERE until>?", (now,)))

    def snooze_alert(self, alert_id, seconds, now=None):
        now = time.time() if now is None else now
        if seconds not in {600, 3600, 86400} or not math.isfinite(now):
            raise ValueError("Choose 10 minutes, 1 hour, or 24 hours")
        row = self.db.execute("SELECT fingerprint FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row or not row[0]:
            raise ValueError("This older alert has no precise matching context. Select a newly recorded alert.")
        self.db.execute("DELETE FROM snoozes WHERE until<=?", (now,))
        active = self.active_snoozes(now)
        if row[0] not in active and len(active) >= 512:
            raise ValueError("Snooze limit reached; clear snoozes first")
        self.db.execute("INSERT OR REPLACE INTO snoozes VALUES(?,?)", (row[0], now + seconds))
        self.db.commit()

    def clear_snoozes(self):
        self.db.execute("DELETE FROM snoozes")
        self.db.commit()

    def retain(self, now=None):
        now = time.time() if now is None else now
        for table, cap in (("events", MAX_EVENTS), ("alerts", MAX_ALERTS)):
            self.db.execute(f"DELETE FROM {table} WHERE ts < ?", (now - 7 * 86400,))
            self.db.execute(f"DELETE FROM {table} WHERE rowid NOT IN "
                            f"(SELECT rowid FROM {table} ORDER BY ts DESC LIMIT ?)", (cap,))
        self.db.execute("DELETE FROM snoozes WHERE until<=?", (now,))
        self.db.commit()

    def rows(self, alerts=False, limit=500):
        if alerts:
            return self.db.execute("SELECT id,ts,rule,severity,title,detail,acknowledged,fingerprint FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return self.db.execute("SELECT id,ts,data FROM events ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()


@dataclasses.dataclass
class Alert:
    rule: str
    severity: str
    title: str
    detail: str
    notify: bool = True
    first_event: str = ""
    authors: str = ""

    def wants_notification(self, high_only=True):
        return self.notify and (not high_only or self.severity == "high")


class Detector:
    def __init__(self, store: Store, auth_threshold=5, auth_window=300, mode='sigma'):
        self.store = store
        from .sigma_engine import SigmaEngine
        from .noise import IgnoreList
        self.mode = mode
        self.sigma = SigmaEngine() if mode == 'sigma' else None
        self.ignores = IgnoreList(store)
        self.argument_context = store.get('argument_context', '1') == '1'
        self.auth_threshold = auth_threshold
        self.auth_window = auth_window
        self.failures = collections.OrderedDict()
        self.history_failures = collections.OrderedDict()
        self.cooldown = collections.OrderedDict()
        self.behavior = BehaviorCorrelator()
        self.chokepoints = Chokepoints()
        self.muted = set(filter(None, store.get("muted_rules").split(",")))
        try:
            self.watched_networks = network_watchlist(store.get("network_watchlist"))
        except ValueError:
            self.watched_networks = ()
            # Do not silently ignore a damaged destination configuration.
            raise ValueError("Invalid saved destination watchlist; review the local state configuration")
        try:
            self.learning_until = float(store.get("learning_until", "0"))
            if not math.isfinite(self.learning_until):
                self.learning_until = 0
        except ValueError:
            self.learning_until = 0

    def reset_correlation(self):
        self.failures.clear()
        self.history_failures.clear()
        self.cooldown.clear()
        self.behavior = BehaviorCorrelator()
        self.chokepoints = Chokepoints()

    def process(self, event: Event, now=None, historical=False) -> list[Alert]:
        now = time.time() if now is None else now
        application_matches = None
        if event.kinds == {'APPLICATION_LOG'}:
            # Application messages are a separate opt-in input. Save metadata
            # only for matching messages; ordinary journal noise is discarded.
            application_matches = self.sigma.detect(event) if self.sigma else []
            if not application_matches:
                return []
        if not self.store.event(event):
            return []
        # Recent history is analyzed locally without training or notifications.
        if event.timestamp < now - (7 * 86400 if historical else 600) or event.timestamp > now + 60:
            self.store.commit()
            return []
        clock = event.timestamp if historical else now
        alerts = []
        result = event.result.lower()
        resolver_alerts = {
            "DNSSEC_FAILURE": ("dnssec-validation", "DNSSEC validation failed",
                "The resolver rejected DNS data during cryptographic validation. Possible spoofing, a broken DNS zone, trust-anchor problems or clock issues; investigate before concluding an attack."),
            "DNSSEC_DOWNGRADE": ("dnssec-downgrade", "DNSSEC validation was downgraded",
                "The resolver reported disabling DNSSEC after detecting incompatible server behavior. This can be a downgrade attack or server incompatibility."),
            "DNSSEC_TRUST_ANCHOR": ("dnssec-trust-anchor", "DNSSEC trust anchor was revoked",
                "The resolver reported a revoked trust anchor. Review resolver/software updates and validation coverage; this is not by itself proof of spoofing."),
        }
        for kind, (rule, title, detail) in resolver_alerts.items():
            if kind in event.kinds:
                alerts.append(Alert(rule, "high", title, detail))
        if "USER_AUTH" in event.kinds and result in {"failed", "failure", "no", "0"}:
            key = (event.records[0].node, clean(event.get("acct", "unknown"), 128), clean(event.get("addr", "local"), 128))
            failures = self.history_failures if historical else self.failures
            bucket = failures.setdefault(key, collections.deque(maxlen=100))
            failures.move_to_end(key)
            while len(failures) > 1024:
                failures.popitem(last=False)
            # Arrival time prevents crafted/out-of-order event timestamps from
            # poisoning correlation windows. Event timestamps still gate age.
            bucket.append(clock)
            current = [value for value in bucket if 0 <= clock - value <= self.auth_window]
            bucket.clear()
            bucket.extend(current)
            if len(bucket) >= self.auth_threshold:
                alerts.append(Alert("auth-burst", "high", "Repeated authentication failures",
                    f"{len(bucket)} USER_AUTH failures in {self.auth_window}s; host={key[0]}, account={key[1]}, address={key[2]}. Could be a mistyped password or an attack."))
        elif "USER_AUTH" in event.kinds and result in {"yes", "success", "1"}:
            failures = self.history_failures if historical else self.failures
            failures.pop((event.records[0].node, clean(event.get("acct", "unknown"), 128),
                          clean(event.get("addr", "local"), 128)), None)
        if "CONFIG_CHANGE" in event.kinds:
            disabled = event.get("audit_enabled", event.get("enabled")) == "0" and result in {"yes", "success", "1"}
            alerts.append(Alert("audit-config", "high" if disabled else "medium",
                "Auditing disabled" if disabled else "Audit configuration event",
                f"op={clean(event.get('op', 'unknown'))}; result={clean(result)}; auid={clean(event.get('auid'))}. Check whether you authorized this change."))
        if event.kinds & {"DAEMON_END", "DAEMON_ABORT", "DAEMON_ERR", "DAEMON_LOST"}:
            alerts.append(Alert("audit-health", "high", "Audit collection health event",
                f"types={clean(','.join(sorted(event.kinds)))}. Audit coverage may be interrupted; check auditd."))
        if event.kinds & {"AVC", "USER_AVC", "SELINUX_ERR", "SECCOMP"}:
            apparmor = event.get("apparmor")
            policy_detail = (f" AppArmor={clean(apparmor)}; profile={clean(event.get('profile'))}; "
                             f"operation={clean(event.get('operation'))}; target={clean(event.get('name'))}; "
                             f"denied_mask={clean(event.get('denied_mask'))}." if apparmor else "")
            title = "AppArmor blocked an operation" if apparmor == "DENIED" else "Security policy event"
            alerts.append(Alert("policy-denial", "medium", title,
                f"types={clean(','.join(sorted(event.kinds)))}; exe={clean(event.get('exe'))}." +
                policy_detail + " A policy event alone is not proof of compromise."))
        keys = set(event.get("key").split("\x01"))
        if result in {"yes", "success", "1"} and keys & {"sentinel_identity", "sentinel_privilege", "sentinel_audit", "sentinel_kernel"}:
            alerts.append(Alert("sensitive-change", "high", "Monitored security-sensitive change",
                f"audit key={clean(event.get('key'))}; exe={clean(event.get('exe'))}; auid={clean(event.get('auid'))}. Requires matching audit watch rules."))
        exe = event.get("exe")
        arch, syscall = event.get("arch").lower(), event.get("syscall")
        successful = result in {"yes", "success", "1"}
        persistence = persistence_changes(event)
        for item in persistence:
            alerts.append(Alert(item.rule, item.severity, item.title,
                f"target={clean(item.target, 512)}; operation={item.operation}; exe={clean(exe)}; "
                f"auid={clean(event.get('auid'))}; euid={clean(event.get('euid'))}. "
                "Captured successful write-capable/mutation/attribute operation at a persistence location. "
                "This does not prove the file contains a working or unauthorized startup action. Verify planned changes."))
        if "SYSCALL" in event.kinds:
            # Existing broader watches can win before a DNS overlay is loaded.
            dns_target = dns_configuration_target(event) if keys & {
                "sentinel_config_change", "sentinel_network_config", "identity_changes"} else ""
            if successful and dns_target and "sentinel_dns_config" not in keys:
                alerts.append(Alert("dns-config-change", "high", "DNS-related configuration changed",
                    f"exe={clean(exe)}; target={dns_target}; auid={clean(event.get('auid'))}. "
                    "Review possible local name-resolution redirection; legitimate administration can also change this file. This is not evidence of a forged DNS reply."))
            # Failed access attempts are evidence too; change alerts require
            # success, so a blocked write is never described as a real change.
            for matched_keys, rule, severity, title in KEY_SIGNALS:
                if persistence and rule in {'persistence-change', 'configuration-change', 'system-file-change', 'package-config', 'privilege-policy'}:
                    continue
                if dns_target and rule in {"configuration-change", "network-policy-change", "identity-change"}:
                    continue
                if keys & matched_keys and (successful or rule == "access-denied"):
                    if rule == "access-denied" and (successful or event.get("exit") not in {"-13", "-1"}):
                        continue
                    target = clean(event.get("name"), 256)
                    alerts.append(Alert(rule, severity, title,
                        f"key={clean(','.join(sorted(keys & matched_keys)))}; exe={clean(exe)}; "
                        f"target={target}; auid={clean(event.get('auid'))}; result={clean(result)}. Verify whether this was authorized."))
            if successful and (syscall == MEMORY_WRITE_CALLS.get(arch) or
                               event.get("ptrace_request") in {"4", "5", "6"}):
                alerts.append(Alert("process-injection", "high", "A process memory-write operation succeeded",
                    f"exe={clean(exe)}; syscall={clean(syscall)}; auid={clean(event.get('auid'))}. Debuggers can also do this; inspect the originating session."))
            if successful and event.get("bpf_command") == "5":
                alerts.append(Alert("bpf-program-load", "high", "An eBPF program was loaded",
                    f"exe={clean(exe)}; auid={clean(event.get('auid'))}. Review kernel instrumentation and security tooling changes."))
        pending = event.get("exit") == "-115" and result in {"no", "failed", "failure", "0"}
        destinations = []
        if "SYSCALL" in event.kinds and syscall in CONNECT_CALLS.get(arch, set()) and (successful or pending):
            destinations = network_destinations(event)
            matched = [(address, port) for address, port in destinations
                       if any(address in network or
                              (isinstance(address, ipaddress.IPv6Address) and
                               address.ipv4_mapped is not None and address.ipv4_mapped in network)
                              for network in self.watched_networks)]
            if matched:
                targets = ", ".join(f"[{address}]:{port}" for address, port in matched)
                alerts.append(Alert("network-watchlist", "high", "Connection to a watched destination",
                    f"exe={clean(exe)}; destination={targets}. Matched your explicit IP/CIDR watchlist; " +
                    ("nonblocking attempt in progress, completion unknown." if pending else "connection syscall succeeded.")))
            if destinations and any(exe.startswith(prefix) for prefix in ("/tmp/", "/var/tmp/", "/dev/shm/")):
                alerts.append(Alert("network-temp-exec", "high", "Temporary-directory executable initiated a network connection",
                    f"exe={clean(exe)}; destinations=" + ", ".join(f"[{address}]:{port}" for address, port in destinations) +
                    ("; nonblocking completion unknown." if pending else "; connect succeeded.") + " Review the executable and its origin."))
        execution = "SYSCALL" in event.kinds and syscall in EXEC_CALLS.get(arch, set())
        for finding in direct_signals(event, execution):
            alerts.append(Alert(finding.rule, finding.severity, clean(finding.title), clean(finding.detail, 8192)))
        if 'DAEMON_START' in event.kinds:
            self.chokepoints.reset_host(historical, event.records[0].node)
        attempts = []
        if ('SYSCALL' in event.kinds and syscall in CONNECT_CALLS.get(arch, set()) and
                (successful or event.get('exit') in {'-115', '-111', '-110', '-113', '-101', '-13', '-1'})):
            attempts = network_destinations(event)
        for finding in self.chokepoints.observe(event, process_identity(event, historical), execution,
                attempts, persistence):
            alerts.append(Alert(finding.rule, finding.severity, clean(finding.title), clean(finding.detail, 8192), first_event=finding.first_event))
        if execution and successful and exe.startswith(('/tmp/', '/var/tmp/', '/dev/shm/', '/home/', '/run/user/')) and exe.rsplit('/', 1)[-1] in {'sshd', 'systemd', 'crond', 'cron', 'udevd', 'systemd-udevd', 'kthreadd', 'kworker'}:
            alerts.append(Alert('process-masquerade', 'high', 'System-service name executed from a writable location',
                f"exe={clean(exe)}; auid={clean(event.get('auid'))}. Name/location mismatch can indicate masquerading; verify package ownership and intended use. Names alone do not establish identity."))
        for finding in self.behavior.observe(event, historical, self.auth_threshold, self.auth_window, execution, destinations):
            alerts.append(Alert(finding.rule, "high", finding.title, finding.detail, first_event=finding.first_event))
        if execution and successful and exe.startswith(("/memfd:", "memfd:")):
            alerts.append(Alert("memory-exec", "high", "An anonymous memory-backed executable was launched",
                f"exe={clean(exe)}; uid={clean(event.get('uid'))}; euid={clean(event.get('euid'))}. Review the executable's origin; legitimate loaders can also use memfd."))
        if execution and event.get("euid") == "0" and result in {"yes", "success", "1"} and exe.startswith("/") and len(exe) <= 4096:
            if self.mode == 'prototype' and not historical and self.learning_until == 0:
                self.learning_until = now + 86400
                self.store.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)",
                                      ("learning_until", str(self.learning_until)))
            known = self.store.db.execute("SELECT 1 FROM baseline WHERE exe=?", (exe,)).fetchone()
            if any(exe.startswith(prefix) for prefix in ("/tmp/", "/var/tmp/", "/dev/shm/")):
                alerts.append(Alert("root-temp-exec", "high", "Root executed a program from a temporary directory",
                    f"exe={clean(exe)}; auid={clean(event.get('auid'))}. Verify the executable and originating session."))
            elif any(exe.startswith(prefix) for prefix in ("/home/", "/run/user/")):
                alerts.append(Alert("root-user-exec", "high", "Root executed a program under a user directory",
                    f"exe={clean(exe)}; auid={clean(event.get('auid'))}. Possible privilege abuse or intentional administration; verify the executable."))
            elif self.mode == 'prototype' and not historical and now < self.learning_until:
                count = self.store.db.execute("SELECT COUNT(*) FROM baseline").fetchone()[0]
                if count < MAX_BASELINE:
                    self.store.db.execute("INSERT OR IGNORE INTO baseline VALUES(?)", (exe[:4096],))
            elif self.mode == 'prototype' and not historical and not known:
                alerts.append(Alert("new-root-exec", "medium", "Root executable outside the learned baseline",
                    f"exe={clean(exe)}; auid={clean(event.get('auid'))}. A new executable is unusual, not proof of compromise."))
        if self.sigma is not None:
            # Sigma owns signatures; local supplements cover reader health,
            # explicit watchlists, policy denials and ordered event sequences.
            alerts = [a for a in alerts if a.rule in LOCAL_SUPPLEMENTS or a.rule.startswith('behavior-')
                      or a.rule == 'auth-success-after-failures']
            groups = {}
            for match in application_matches if application_matches is not None else self.sigma.detect(event):
                groups.setdefault(match['logic_digest'], []).append(match)
            for group_matches in groups.values():
                primary = group_matches[0]
                authors = '; '.join(dict.fromkeys(m['author'] for m in group_matches))
                detail = 'SigmaHQ rule match; author(s): ' + clean(authors, 1024) + '\n' + '\n'.join(
                    f"{clean(m['title'])} · {m['id']} · {m['source']} · status={m['status']}; level={m['level']}"
                    for m in group_matches)
                detail += '\n' + clean(primary['description'], 2048) + '\nFalse positives: ' + clean(primary['falsepositives'], 1024)
                detail += '\nCaptured record matched upstream logic. This is not proof of execution, a write or compromise; verify syscall/result and PATH roles.'
                detail += '\nMatched selection(s): ' + clean(primary.get('matched_selections', []), 1024)
                if primary.get('matched_argument_fields'):
                    detail += '\nMatched argument field(s): ' + clean(primary['matched_argument_fields'], 1024)
                if any(m.get('argument_matching') for m in group_matches):
                    detail += '\nBounded arguments/keywords were checked in memory. Complete single-record EXECVE only: at most 16 arguments, 512 bytes each and 4096 bytes total. Missing/split/oversized arguments are not matched; saved context follows the argument-context setting.'
                if primary.get('source_kind') == 'application':
                    detail += '\nSelected journal service: ' + clean(event.get('unit'), 128) + '; scope=' + clean(event.get('source_scope'), 16)
                    detail += '; application mapping=' + clean(event.get('application_product'), 32)
                    detail += '\nMatched static rule indicators: ' + clean(primary.get('matched_indicators', []), 1024)
                    detail += '\nApplication error text was checked in memory and is not saved. A configured product mapping and journal metadata do not prove application identity or exploitation; application bugs can match.'
                from .sigma_engine import LEVELS
                severity = max((LEVELS[m['level']] for m in group_matches), key={'low': 0, 'medium': 1, 'high': 2}.get)
                alerts.append(Alert('sigma:' + primary['id'], severity, primary['title'], detail, authors=authors))
        # Save one bounded, redacted argument view only with matching alerts.
        # No argv is added to event summaries, notification bodies or diagnostics.
        argument_context = describe_arguments(event) if self.argument_context and alerts else ''
        if argument_context:
            alerts = [dataclasses.replace(alert, detail=alert.detail + '\n\n' + argument_context) for alert in alerts]
        # Key-specific throttling retains immediate high-impact changes while
        # bounding notification floods; every matching event remains in history.
        emitted = []
        pending_cooldown = []
        snoozes = self.store.active_snoozes(now)
        for alert in alerts:
            if alert.rule in self.muted:
                continue
            context = [alert.rule, sorted({
                (row.kind, row.context_digest) for row in event.records
                if row.kind not in {"EOE", "CWD", "PROCTITLE", "EXECVE"}
                or ((alert.rule.startswith('sigma:') or argument_context) and row.kind == 'EXECVE' and row.sigma_arguments)
            })]
            if alert.rule in PERSISTENCE_RULES:
                context.append(sorted(item.target for item in persistence if item.rule == alert.rule))
            fingerprint = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()
            noise_context = {key: event.get(key) for key in ('exe', 'profile', 'operation', 'denied_mask', 'name')}
            noise_context['node'] = event.records[0].node
            if self.ignores.match(alert.rule, fingerprint, noise_context, now):
                continue
            group = (historical, alert.rule, fingerprint)
            if alert.rule == "auth-burst":
                group = (historical, alert.rule, key)
            previous = self.cooldown.get(group, -math.inf)
            detail = ("Historical finding; no desktop notification. " if historical else "") + alert.detail + f" Evidence: audit event {clean(event.identity)}."
            self.store.alert(alert.rule, alert.severity, alert.title, detail, clock, fingerprint,
                             event.identity, alert.first_event, historical)
            if 0 <= clock - previous < 60:
                continue
            pending_cooldown.append((group, clock))
            emitted.append(dataclasses.replace(alert, detail=detail,
                                              notify=not historical and fingerprint not in snoozes))
        self.store.commit()
        for group, clock in pending_cooldown:
            self.cooldown[group] = clock
            self.cooldown.move_to_end(group)
        while len(self.cooldown) > 2048:
            self.cooldown.popitem(last=False)
        return emitted


RULES = {
    **CHOKEPOINT_RULES,
    **{rule: 'Successful watched persistence-location change: ' + rule.removeprefix('persistence-') for rule in sorted(PERSISTENCE_RULES)},
    'behavior-user-persistence': 'Temporary/memory-backed user execution followed by a captured persistence change in the same observed process',
    'process-masquerade': 'System-service executable basename launched from a writable/user location; investigate identity',
    "auth-success-after-failures": "Authentication success following repeated failures for the same host/account/address",
    "behavior-persistence": "Risky root execution then a persistence change by the same observed process within five minutes",
    "behavior-network": "Risky root execution then a public-IP connect by the same observed process within five minutes",
    "dnssec-validation": "systemd-resolved DNSSEC validation failure; possible spoofing or configuration trouble",
    "dnssec-downgrade": "systemd-resolved reports DNSSEC validation disabled after downgrade",
    "dnssec-trust-anchor": "systemd-resolved reports a revoked DNSSEC trust anchor",
    **{rule: title + " (matching audit collection key required)"
       for _, rule, _, title in KEY_SIGNALS},
    "process-injection": "Successful ptrace memory write or process_vm_writev; debuggers may be legitimate",
    "bpf-program-load": "Successful BPF_PROG_LOAD; legitimate monitoring tools can also load eBPF",
    "memory-exec": "Successful execve/execveat of a /memfd: executable",
    "root-user-exec": "Successful root execution from /home or /run/user (review for privilege abuse)",
    "network-watchlist": "Successful or in-progress connect to your explicit destination IP/CIDR watchlist",
    "network-temp-exec": "Successful or in-progress IP connect by an executable under /tmp, /var/tmp, or /dev/shm",
    "auth-burst": "5 failed USER_AUTH events per account/address in 5 minutes",
    "audit-config": "Audit configuration changes (high if disabling)",
    "audit-health": "Audit daemon errors, shutdown, abort, or loss records",
    "policy-denial": "AVC / USER_AVC / SELINUX_ERR / SECCOMP policy events",
    "sensitive-change": "Successful events carrying sentinel_* security watch keys",
    "root-temp-exec": "Successful root execve/execveat from /tmp, /var/tmp, /dev/shm",
    "new-root-exec": "New successful root executable after the 24-hour learning period",
}
