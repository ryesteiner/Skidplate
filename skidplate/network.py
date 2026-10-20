"""Bounded read-only snapshots of the app's network namespace. No network I/O."""
from pathlib import Path
import os
import queue
import re
import threading
import time

from .investigate import endpoint, read_text, proc_identity, STATES
from .core import clean

TABLES = ('tcp', 'tcp6', 'udp', 'udp6')
MAX_ROWS = 4096


def attach_owners(result, *, root=Path('/proc'), clock=time.monotonic):
    """Observe descriptor holders, with pinned proc directories and rechecked identity.

    A holder may have inherited/received a socket and is not necessarily its creator.
    Never infer a PID from the socket UID. Visibility remains ordinary-user only.
    """
    wanted = {row['inode'] for row in result['rows'] if row['inode'] != '0'}
    owners = {inode: [] for inode in wanted}
    notes = set()
    deadline, links = clock() + 2, 0
    if wanted:
        try:
            with os.scandir(root) as entries:
                for index, entry in enumerate(entries):
                    if index >= 4096 or clock() > deadline or links >= 4096:
                        notes.add('Process scan limit reached; holder visibility is partial.')
                        break
                    if not re.fullmatch(r'[1-9][0-9]{0,6}', entry.name) or int(entry.name) > 4194304:
                        continue
                    pidfd = None
                    try:
                        pidfd = os.open(root / entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                        # Pinned proc directory cannot redirect to a reused PID after exit.
                        directory = Path('/proc/self/fd') / str(pidfd)
                        before = proc_identity(directory)
                        if len(before[3]) > 4096:
                            continue
                        matches = {}
                        with os.scandir(directory / 'fd') as descriptors:
                            for number, descriptor in enumerate(descriptors):
                                if number >= 256 or clock() > deadline:
                                    notes.add('Descriptor scan limit reached; holder visibility is partial.')
                                    break
                                try:
                                    target = os.readlink(descriptor.path)
                                except OSError:
                                    notes.add('Some process descriptors were unreadable or changed.')
                                    continue
                                match = re.fullmatch(r'socket:\[([0-9]{1,20})\]', target)
                                if match and match[1] in wanted:
                                    matches[match[1]] = descriptor.name
                        after = proc_identity(directory)
                        if (after[0], after[3]) != (before[0], before[3]):
                            notes.add('A process changed during lookup; its holder matches were discarded.')
                            continue
                        owner = {'pid': entry.name, 'start_ticks': str(before[0]),
                                 'application': clean(Path(before[3]).name, 80), 'exe': clean(before[3], 4096)}
                        for inode, descriptor in matches.items():
                            if len(owners[inode]) >= 8 or links >= 4096:
                                notes.add('Shared-holder result limit reached; visibility is partial.')
                                continue
                            try:
                                if os.readlink(directory / 'fd' / descriptor) != f'socket:[{inode}]':
                                    notes.add('A socket descriptor changed during holder lookup.')
                                    continue
                            except OSError:
                                notes.add('Some process descriptors were unreadable or changed.')
                                continue
                            owners[inode].append(owner)
                            links += 1
                    except (OSError, ValueError, IndexError):
                        notes.add('Some process identities/descriptors are unavailable with current permissions or exited.')
                    finally:
                        if pidfd is not None:
                            os.close(pidfd)
        except OSError:
            notes.add('Process directory unavailable; holder visibility unknown.')
    for row in result['rows']:
        row['owners'] = owners.get(row['inode'], [])
    result['owner_notes'] = sorted(notes)
    return result


def collect(*, root=Path('/proc/self'), clock=time.monotonic):
    result = {'captured': time.time(), 'namespace': '', 'tables': 0, 'complete': True,
              'active': 0, 'tcp': 0, 'udp': 0, 'listening': 0, 'rows': [], 'notes': []}
    deadline = clock() + 2
    try:
        namespace = os.readlink(root / 'ns' / 'net')
        if not re.fullmatch(r'net:\[[0-9]{1,20}\]', namespace):
            raise ValueError('Invalid namespace identity')
        result['namespace'] = namespace
        for table in TABLES:
            try:
                if clock() > deadline:
                    raise ValueError('Snapshot time limit reached')
                data = read_text(root / 'net' / table, 1024 * 1024)
                lines = data.splitlines()
                if not lines or 'local_address' not in lines[0]:
                    raise ValueError('Unexpected socket table header')
                result['tables'] += 1
                seen = set()
                for line in lines[1:]:
                    if len(result['rows']) >= MAX_ROWS or clock() > deadline:
                        raise ValueError('Snapshot row/time limit reached')
                    cols = line.split()
                    if (len(cols) < 10 or not re.fullmatch(r'[0-9]{1,20}', cols[9]) or
                            not re.fullmatch(r'[0-9]{1,10}', cols[7]) or
                            not re.fullmatch(r'[0-9A-F]{2}', cols[3])):
                        raise ValueError('Unexpected socket row')
                    local, remote = endpoint(cols[1]), endpoint(cols[2])
                    # Namespace tables may contain inode zero for TIME_WAIT; endpoints identify those rows.
                    identity = table, cols[9], local, remote
                    if identity in seen:
                        continue
                    seen.add(identity)
                    tcp = table.startswith('tcp')
                    active = cols[3] == '01' and (tcp or any(c != '0' for c in cols[2].replace(':', '')))
                    listening = tcp and cols[3] == '0A'
                    result['tcp' if tcp else 'udp'] += int(active)
                    result['listening'] += int(listening)
                    result['rows'].append({'protocol': table.upper(), 'local': local, 'remote': remote,
                        'state': STATES.get(cols[3], 'UNKNOWN'), 'uid': cols[7], 'inode': cols[9],
                        'active': active, 'listening': listening})
            except (OSError, ValueError):
                result['complete'] = False
                result['notes'].append(f'{table.upper()} unavailable, malformed or scan limit reached.')
        if os.readlink(root / 'ns' / 'net') != namespace:
            raise ValueError('Namespace changed during snapshot')
    except (OSError, ValueError):
        result.update(tables=0, complete=False, rows=[], tcp=0, udp=0, listening=0)
        result['notes'].append('Namespace identity unavailable or changed; snapshot discarded.')
    result['active'] = result['tcp'] + result['udp']
    return result


class NetworkSampler:
    """One finite worker, one result slot; GUI polls without blocking ingestion."""
    def __init__(self):
        self.results = queue.Queue(maxsize=1)
        self.thread = None
        self.next_due = 0
        self.closed = False

    def request(self, force=False):
        if self.closed or self.thread is not None and self.thread.is_alive():
            return
        if not force and time.monotonic() < self.next_due:
            return
        self.next_due = time.monotonic() + 5
        def worker():
            try:
                result = collect()
                attach_owners(result)
            except Exception:
                result = {'captured': time.time(), 'namespace': '', 'tables': 0, 'complete': False,
                          'active': 0, 'tcp': 0, 'udp': 0, 'listening': 0, 'rows': [],
                          'notes': ['Network snapshot failed; visibility unknown.']}
            try:
                self.results.put_nowait(result)
            except queue.Full:
                pass
        self.thread = threading.Thread(target=worker, daemon=True, name='skidplate-network')
        self.thread.start()

    def poll(self):
        try:
            return self.results.get_nowait()
        except queue.Empty:
            return None

    def close(self):
        self.closed = True
