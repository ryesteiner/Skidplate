"""Bounded, unprivileged reads of specific systemd-resolved journal events.

No DNS queries, packet capture, resolver configuration writes or elevation.
The fixed journalctl command never invokes a shell or pager.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import selectors
import subprocess
import threading
import time

from .core import MAX_LINE, Record

RESOLVER_EXE = "/usr/lib/systemd/systemd-resolved"
RESOLVER_UNIT = "systemd-resolved.service"
DNSSEC_EVENTS = {
    "1675d7f172174098b1108bf8c7dc8f5d": "DNSSEC_FAILURE",
    "36db2dfa5a9045e1bd4af5f93e1cf057": "DNSSEC_DOWNGRADE",
    "4d4408cfd0d144859184d1e65d7c8a65": "DNSSEC_TRUST_ANCHOR",
}
MAX_BATCH = 200
MAX_OUTPUT = 1024 * 1024
QUERY_TIMEOUT = 3


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate journal field")
        result[key] = value
    return result


def parse_resolver_line(line):
    if len(line) > MAX_LINE:
        raise ValueError("Oversized resolver record")
    try:
        data = json.loads(line, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Invalid resolver record") from exc
    if not isinstance(data, dict) or not all(isinstance(value, str) for value in data.values()):
        raise ValueError("Resolver metadata must contain single string fields")
    if data.get("_SYSTEMD_UNIT") != RESOLVER_UNIT or data.get("_EXE") != RESOLVER_EXE:
        raise ValueError("Unexpected journal event origin")
    kind = DNSSEC_EVENTS.get(data.get("MESSAGE_ID"))
    cursor = data.get("__CURSOR", "")
    timestamp = data.get("__REALTIME_TIMESTAMP", "")
    if kind is None or not re.fullmatch(r"[A-Za-z0-9_=;:-]{1,2048}", cursor) or not re.fullmatch(r"[0-9]{1,18}", timestamp):
        raise ValueError("Unexpected resolver event metadata")
    serial = hashlib.sha256(cursor.encode()).hexdigest()
    message = data.get("MESSAGE", "")
    if not message:
        raise ValueError("Missing resolver event context")
    # Different questions/errors/servers must not share a selected-event snooze.
    # Keep only the digest, never the raw message or browsing domains in history.
    digest = hashlib.sha256(json.dumps([kind, message]).encode()).hexdigest()
    return Record(kind, int(timestamp) / 1_000_000, serial,
                  {"exe": RESOLVER_EXE, "res": "failed"}, "resolved", digest), cursor


def journal_command(cursor, since):
    if cursor and not re.fullmatch(r"[A-Za-z0-9_=;:-]{1,2048}", cursor):
        raise ValueError("Invalid journal cursor")
    command = ["/usr/bin/journalctl", "--system", "--no-pager", "--output=json",
               "--output-fields=MESSAGE_ID,MESSAGE,_SYSTEMD_UNIT,_EXE,__REALTIME_TIMESTAMP,__CURSOR",
               f"--lines=+{MAX_BATCH}", f"_SYSTEMD_UNIT={RESOLVER_UNIT}",
               f"_EXE={RESOLVER_EXE}"]
    command += [f"MESSAGE_ID={value}" for value in DNSSEC_EVENTS]
    command.append(f"--after-cursor={cursor}" if cursor else f"--since=@{int(since)}")
    return command


def bounded_query(command, stopped):
    """Read stdout/stderr under a combined byte cap and a wall-clock deadline."""
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={"LANG": "C", "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
            close_fds=True) as process:
        try:
            outputs = {"out": bytearray(), "err": bytearray()}
            deadline = time.monotonic() + QUERY_TIMEOUT
            total = 0
            with selectors.DefaultSelector() as selector:
                for stream, name in ((process.stdout, "out"), (process.stderr, "err")):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    if stopped.is_set() or time.monotonic() >= deadline:
                        raise ValueError("Resolver query cancelled or timed out")
                    for key, _ in selector.select(timeout=0.05):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > MAX_OUTPUT:
                            raise ValueError("Resolver query exceeded its output limit")
                        outputs[key.data].extend(chunk)
            remaining = max(0.01, deadline - time.monotonic())
            code = process.wait(timeout=remaining)
            if code or outputs["err"]:
                raise ValueError("Resolver journal unavailable or incompletely readable")
            return bytes(outputs["out"]).decode("utf-8", errors="strict")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=1)


class ResolverFollower:
    """One background query at a time; acknowledge cursor only after processing."""
    def __init__(self, now=None):
        now = time.time() if now is None else now
        self.since = now - 7 * 86400
        self.cursor = ""
        self.status = "DNSSEC telemetry connecting; validation mode unverified"
        self.stopped = threading.Event()
        self.results = queue.Queue(maxsize=1)
        self.worker = None
        self.pending = None
        self.next_query = 0

    def _query(self, command):
        try:
            text = bounded_query(command, self.stopped)
            lines = [line for line in text.splitlines() if line.strip() and line.strip() != "-- No entries --"]
            if len(lines) > MAX_BATCH:
                raise ValueError("Unexpected resolver batch size")
            rows = [parse_resolver_line(line) for line in lines]
            self.results.put_nowait((rows, None))
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            self.results.put_nowait(([], "DNSSEC telemetry unavailable: check journal access, cursor and reader limits"))

    def poll(self, now=None):
        now = time.monotonic() if now is None else now
        if self.stopped.is_set() or self.pending is not None:
            return []
        if self.worker is not None:
            if self.worker.is_alive():
                return []
            rows, error = self.results.get_nowait()
            self.worker = None
            self.next_query = now + (0.5 if len(rows) == MAX_BATCH else 10)
            if error:
                self.status = error
                return []
            self.status = "DNSSEC journal read succeeded; validation mode and coverage unverified"
            if rows:
                self.pending = rows
                return [row for row, _ in rows]
        if now >= self.next_query:
            self.worker = threading.Thread(target=self._query,
                args=(journal_command(self.cursor, self.since),), daemon=True)
            self.worker.start()
        return []

    def acknowledge(self):
        if self.pending:
            self.cursor = self.pending[-1][1]
            self.pending = None

    def retry_pending(self):
        """Keep the same cursor when persistence/processing failed."""
        self.pending = None

    def close(self):
        self.stopped.set()
