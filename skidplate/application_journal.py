"""Opt-in, bounded reads of exact application journal services; no elevation."""
from dataclasses import dataclass
import hashlib
import json
import os
import queue
import re
import subprocess
import threading
import time

from .core import Record
from .resolver import bounded_query, _unique_object

PRODUCTS = {'python', 'ruby_on_rails', 'nodejs'}
UNIT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,119}\.service')
CURSOR = re.compile(r'[A-Za-z0-9_=;:-]{1,2048}')
MAX_BATCH = 100


@dataclass(frozen=True)
class Source:
    scope: str
    product: str
    unit: str

    def __post_init__(self):
        if self.scope not in {'user', 'system'} or self.product not in PRODUCTS or not UNIT.fullmatch(self.unit):
            raise ValueError('Choose user/system, python/ruby_on_rails/nodejs and an exact simple .service name')

    @property
    def key(self):
        return f'{self.scope}:{self.product}:{self.unit}'


def parse_sources(text):
    if not isinstance(text, str) or len(text) > 2048:
        raise ValueError('Application source list is too long')
    entries = [entry.strip() for entry in text.split(';') if entry.strip()]
    if len(entries) > 8:
        raise ValueError('At most eight application services are supported')
    sources = []
    for entry in entries:
        parts = entry.split(':', 2)
        if len(parts) != 3:
            raise ValueError('Use scope:product:unit.service separated by semicolons')
        source = Source(*parts)
        # One explicit product mapping per journal source avoids accidental
        # duplicate interpretations of the same entry under several runtimes.
        if any((s.scope, s.unit) == (source.scope, source.unit) for s in sources):
            raise ValueError('A service can have only one application product mapping')
        sources.append(source)
    return tuple(sources)


def journal_command(source, cursor, since):
    if cursor and not CURSOR.fullmatch(cursor):
        raise ValueError('Invalid application journal cursor')
    unit_field = '_SYSTEMD_USER_UNIT' if source.scope == 'user' else '_SYSTEMD_UNIT'
    command = ['/usr/bin/journalctl', '--' + source.scope, '--no-pager', '--output=json',
               '--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,_SYSTEMD_USER_UNIT,_EXE,_PID,_UID,_MACHINE_ID,_BOOT_ID,__REALTIME_TIMESTAMP,__CURSOR',
               f'--lines=+{MAX_BATCH}', f'{unit_field}={source.unit}']
    if source.scope == 'user':
        command.append(f'_UID={os.getuid()}')
    command.append('--after-cursor=' + cursor if cursor else f'--since=@{int(since)}')
    return command


def parse_entry(line, source):
    if len(line) > 65536:
        raise ValueError('Oversized application journal entry')
    try:
        data = json.loads(line, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError('Invalid application journal JSON') from exc
    if not isinstance(data, dict) or any(not isinstance(v, str) for v in data.values()):
        raise ValueError('Application journal requires single string fields')
    unit_field = '_SYSTEMD_USER_UNIT' if source.scope == 'user' else '_SYSTEMD_UNIT'
    if data.get(unit_field) != source.unit or (source.scope == 'user' and data.get('_UID') != str(os.getuid())):
        raise ValueError('Application journal origin mismatch')
    cursor, timestamp = data.get('__CURSOR', ''), data.get('__REALTIME_TIMESTAMP', '')
    if not CURSOR.fullmatch(cursor) or not re.fullmatch(r'[0-9]{1,18}', timestamp):
        raise ValueError('Invalid application journal identity')
    if data.get('PRIORITY') not in {str(i) for i in range(8)}:
        raise ValueError('Invalid application journal priority')
    for key in ('_UID', '_PID'):
        if key in data and (not re.fullmatch(r'[0-9]{1,10}', data[key]) or int(data[key]) > 4294967295):
            raise ValueError('Invalid application subject metadata')
    if not all(re.fullmatch(r'[0-9a-f]{32}', data.get(key, '')) for key in ('_MACHINE_ID', '_BOOT_ID')):
        raise ValueError('Invalid application host/boot identity')
    message = data.get('MESSAGE', '')
    if not message or len(message.encode('utf-8')) > 16384:
        raise ValueError('Missing or oversized application message')
    exe = data.get('_EXE', '')
    if len(exe) > 4096 or (exe and not exe.startswith('/')):
        raise ValueError('Invalid application executable metadata')
    # Metadata and digest only reach SQLite. The journal message is transient,
    # repr-hidden, and never becomes an exception message or matched evidence.
    digest = hashlib.sha256(json.dumps([source.key, message], ensure_ascii=True).encode()).hexdigest()
    identity = hashlib.sha256((source.key + cursor).encode()).hexdigest()
    values = {'exe': exe, 'pid': data.get('_PID', ''), 'uid': data.get('_UID', ''),
              'unit': source.unit, 'application_product': source.product,
              'source_scope': source.scope, 'res': 'observed'}
    node = 'journal:' + source.scope + ':' + data['_MACHINE_ID'] + ':' + data['_BOOT_ID']
    return Record('APPLICATION_LOG', int(timestamp) / 1_000_000, identity, values,
                  node, digest, application_message=message), cursor


class ApplicationJournal:
    """One query worker globally; one pending bounded batch until DB commit."""
    def __init__(self, sources=(), now=None):
        self.since = time.time() if now is None else now  # No automatic backfill.
        self.sources = tuple(sources)
        self.cursors, self.statuses = {}, {}
        self.index = 0
        self.status = 'Application journals disabled; select exact services'
        self.stopped = threading.Event()
        self.results = queue.Queue(maxsize=1)
        self.worker = self.pending = None
        self.next_query = 0

    def configure(self, sources):
        if self.worker is not None or self.pending is not None:
            raise ValueError('Application reader is busy; try applying again after the current batch')
        self.sources = tuple(sources)
        self.cursors, self.statuses = {}, {}
        self.since, self.index = time.time(), 0
        self.status = 'Application journals configured; awaiting read' if sources else 'Application journals disabled'

    def _query(self, source):
        try:
            output = bounded_query(journal_command(source, self.cursors.get(source.key, ''), self.since), self.stopped)
            lines = [line for line in output.splitlines() if line.strip() and line.strip() != '-- No entries --']
            if len(lines) > MAX_BATCH:
                raise ValueError('Application batch limit exceeded')
            self.results.put_nowait((source, [parse_entry(line, source) for line in lines], None))
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            self.results.put_nowait((source, [], 'unavailable: check journal access, metadata and reader limits'))

    def poll(self, now=None):
        now = time.monotonic() if now is None else now
        if self.stopped.is_set() or self.pending is not None or not self.sources:
            return []
        if self.worker is not None:
            if self.worker.is_alive():
                return []
            source, rows, error = self.results.get_nowait()
            self.worker = None
            self.index = (self.index + 1) % len(self.sources)
            self.next_query = now + 1
            self.statuses[source.key] = error or ('batch limit reached; backlog may remain; coverage unverified' if len(rows) == MAX_BATCH else 'read completed; coverage/application identity unverified')
            self.status = '\n'.join(f'{key}: {value}' for key, value in self.statuses.items())
            if rows:
                self.pending = source, rows
                return [row for row, _ in rows]
        if now >= self.next_query:
            source = self.sources[self.index]
            self.worker = threading.Thread(target=self._query, args=(source,), daemon=True)
            self.worker.start()
        return []

    def acknowledge(self):
        if self.pending:
            source, rows = self.pending
            self.cursors[source.key] = rows[-1][1]
            self.pending = None

    def retry_pending(self):
        self.pending = None  # Cursor unchanged; requery batch after rollback.

    def close(self):
        self.stopped.set()
