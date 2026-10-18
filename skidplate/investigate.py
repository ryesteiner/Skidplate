"""On-demand read-only /proc snapshots. No signals, DNS, shell or file execution."""
from __future__ import annotations

import ipaddress
import math
import os
from pathlib import Path
import re
import sys
import time

from .core import clean

STATES = {'01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1',
          '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE / UNCONNECTED', '08': 'CLOSE_WAIT',
          '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING', '0C': 'NEW_SYN_RECV'}


def endpoint(value):
    address, port = value.split(':')
    if not re.fullmatch(r'(?:[0-9A-Fa-f]{8}|[0-9A-Fa-f]{32})', address) or not re.fullmatch(r'[0-9A-Fa-f]{4}', port):
        raise ValueError('Invalid socket address')
    raw = bytes.fromhex(address)
    raw = b''.join(raw[i:i+4][::(-1 if sys.byteorder == 'little' else 1)] for i in range(0, len(raw), 4))
    ip = str(ipaddress.ip_address(raw))
    return f'[{ip}]:{int(port, 16)}' if len(raw) == 16 else f'{ip}:{int(port, 16)}'


def read_text(path, limit=65536):
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Process metadata exceeds snapshot limit')
    return data.decode('utf-8', 'replace')


def proc_identity(directory):
    stat = read_text(directory / 'stat', 8192)
    tail = stat.rsplit(')', 1)[1].split()
    return int(tail[19]), int(tail[1]), tail[0], os.readlink(directory / 'exe')


def snapshot(summary, event_time, *, root=Path('/proc'), now=None):
    """Only inspect a local PID with exact executable and valid audit IDs.

    Timestamp/start-time checks reject an obvious reused PID. This is corroboration,
    not proof: old audit summaries lack a process-start token or boot ID.
    """
    result = {'matched': False, 'status': '', 'connections': [], 'notes': [], 'process': {}}
    pid, exe = summary.get('pid', ''), summary.get('exe', '')
    if (not re.fullmatch(r'[0-9]{1,10}', pid) or not 1 <= int(pid) <= 4194304
            or not exe.startswith('/') or len(exe) > 4096):
        result['status'] = 'No usable PID/executable in this saved event.'
        return result
    if summary.get('node') not in {'local', os.uname().nodename}:
        result['status'] = 'Event host does not match this machine; local PID lookup skipped.'
        return result
    if not all(re.fullmatch(r'[0-9]{1,10}', summary.get(key, '')) and
               int(summary[key]) < 4294967294 for key in ('auid', 'session')):
        result['status'] = 'Missing audit login/session identity; live association skipped.'
        return result
    directory = root / str(int(pid))
    deadline = time.monotonic() + 2
    try:
        before = proc_identity(directory)
        if before[3] != exe:
            raise ValueError('PID now has a different executable; no live association made')
        boot = next(int(line.split()[1]) for line in read_text(root / 'stat').splitlines() if line.startswith('btime '))
        started = boot + before[0] / os.sysconf('SC_CLK_TCK')
        now = time.time() if now is None else now
        if not math.isfinite(event_time) or event_time < started - 1 or event_time > now + 60:
            raise ValueError('Saved event predates this process or has an invalid time; possible PID reuse')
        if (read_text(directory / 'loginuid', 32).strip() != summary['auid'] or
                read_text(directory / 'sessionid', 32).strip() != summary['session']):
            raise ValueError('Audit login/session differs; no live association made')
        uid_line = next(line for line in read_text(directory / 'status').splitlines() if line.startswith('Uid:'))
        uids = uid_line.split()[1:3]
        result['process'] = {'pid': pid, 'ppid': str(before[1]), 'state': clean(before[2], 32),
                             'exe': clean(before[3], 4096), 'uid': uids[0], 'euid': uids[1],
                             'start': started}
        inodes = set()
        try:
            with os.scandir(directory / 'fd') as entries:
                for index, entry in enumerate(entries):
                    if index >= 512 or time.monotonic() > deadline:
                        result['notes'].append('File descriptor scan truncated; socket visibility is partial.')
                        break
                    try:
                        link = os.readlink(entry.path)
                    except OSError:
                        result['notes'].append('A descriptor disappeared or was unreadable.')
                        continue
                    match = re.fullmatch(r'socket:\[([0-9]{1,20})\]', link)
                    if match:
                        inodes.add(match[1])
        except OSError:
            result['notes'].append('File descriptors unavailable with current permissions; socket visibility unknown.')
        for table in ('tcp', 'tcp6', 'udp', 'udp6'):
            if not inodes:
                break
            try:
                # These tables are namespace-wide: retain only this PID's socket inodes.
                data = read_text(directory / 'net' / table, 512 * 1024)
                for index, line in enumerate(data.splitlines()[1:]):
                    if index >= 4096 or len(result['connections']) >= 128 or time.monotonic() > deadline:
                        result['notes'].append('Socket scan truncated; visibility is partial.')
                        break
                    cols = line.split()
                    if len(cols) >= 10 and cols[9] in inodes:
                        result['connections'].append({'protocol': table.upper(), 'local': endpoint(cols[1]),
                            'remote': endpoint(cols[2]), 'state': STATES.get(cols[3], 'UNKNOWN'), 'inode': cols[9]})
            except (OSError, ValueError):
                result['notes'].append(f'{table.upper()} table unavailable or too large; visibility is partial.')
        after = proc_identity(directory)
        if (after[0] != before[0] or after[3] != before[3] or
                read_text(directory / 'loginuid', 32).strip() != summary['auid'] or
                read_text(directory / 'sessionid', 32).strip() != summary['session']):
            raise ValueError('Process changed during inspection; discard this snapshot and retry')
        result['matched'] = True
        result['status'] = 'Current process is consistent with saved metadata; association is not proof of identity.'
    except (OSError, ValueError, IndexError, StopIteration) as exc:
        result.update(matched=False, process={}, connections=[], status='Live lookup unavailable: ' + clean(str(exc), 256))
    result['notes'] = list(dict.fromkeys(result['notes']))[:8]
    return result


def containment_guidance(rule):
    steps = ['Preserve the event ID and evidence before changing anything. Verify whether this was expected activity.',
             'Check the exact executable, current process identity and endpoints. A High rule match alone does not prove compromise.']
    if rule in {'policy-denial', 'access-denied'}:
        steps.append('A denied operation may already be blocked. Check the profile/target before changing policy or quarantining files.')
    elif 'network' in rule:
        steps.append('If you confirm an unwanted connection, consider disconnecting the host from the network while investigating. Record the endpoint; an IP may be shared by legitimate services.')
    elif 'persistence' in rule or rule in {'privilege-policy', 'identity-change', 'system-file-change'}:
        steps.append('Review the changed configuration and its owner. Preserve a copy and compare with a known-good version before disabling an identified service or startup entry.')
    else:
        steps.append('If compromise is confirmed, consider isolating the host and stopping the verified offending service using your normal administration tools.')
    steps.append('File quarantine is a separate reviewed action: preserve metadata/hash, identify package ownership, and avoid moving system binaries or deleting evidence. No action is executed here.')
    return '\n\n'.join(steps)
