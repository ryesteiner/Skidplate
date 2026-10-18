"""Saved evidence presentation and bounded, local-only account names."""
import os
from pathlib import Path
import posixpath
import re
import stat

from .signals import UID_CALLS

OPERATIONS = {
    'c000003e': {'0': 'read', '1': 'write', '2': 'open', '18': 'pwrite64', '20': 'writev',
        '42': 'connect', '59': 'execve', '76': 'truncate', '77': 'ftruncate', '82': 'rename',
        '87': 'unlink', '90': 'chmod', '92': 'chown', '257': 'openat', '263': 'unlinkat',
        '264': 'renameat', '268': 'fchmodat', '316': 'renameat2', '322': 'execveat', '437': 'openat2'},
    '40000003': {'3': 'read', '4': 'write', '5': 'open', '11': 'execve', '38': 'rename',
        '295': 'openat', '302': 'renameat', '353': 'renameat2', '358': 'execveat', '362': 'connect', '437': 'openat2'},
    'c00000b7': {'35': 'unlinkat', '38': 'renameat', '56': 'openat', '63': 'read', '64': 'write',
        '203': 'connect', '221': 'execve', '276': 'renameat2', '281': 'execveat', '437': 'openat2'},
}


def operation(event):
    if 'SYSCALL' not in event.kinds:
        return event.get('op') or ', '.join(sorted(event.kinds - {'EOE'}))
    arch, call = event.get('arch').lower(), event.get('syscall')
    name = OPERATIONS.get(arch, {}).get(call) or UID_CALLS.get(arch, {}).get(call, ('', ''))[0]
    return f'{name or "unmapped syscall"} (ABI={arch or "unknown"}, number={call or "unknown"})'


def targets(event):
    rows = [row for row in event.records if row.kind == 'PATH']
    parents = {row.values.get('name', '') for row in rows if row.values.get('nametype') == 'PARENT' and row.values.get('name', '').startswith('/')}
    cwd = next((row.values.get('cwd', '') for row in event.records if row.kind == 'CWD'), '')
    found = []
    for row in rows:
        path, kind = row.values.get('name', ''), row.values.get('nametype', 'NORMAL')
        if kind == 'PARENT' or not path or path == '(null)':
            continue
        if not path.startswith('/'):
            if '/' not in path and parents:
                parent = next(iter(parents)) if len(parents) == 1 else ''
            else:
                parent = cwd
            if not parent.startswith('/'):
                continue
            path = posixpath.join(parent, path)
        item = {'path': posixpath.normpath(path), 'kind': kind}
        if item not in found:
            found.append(item)
        if len(found) == 8:
            break
    return found


def local_accounts(path=Path('/etc/passwd')):
    """Avoid NSS/LDAP lookups. Read only a fixed local file, at most 256KiB."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return {}
        data = os.read(fd, 256 * 1024 + 1)
        if len(data) > 256 * 1024:
            return {}
        accounts = {}
        for line in data.decode('utf-8', 'replace').splitlines()[:4096]:
            fields = line.split(':')
            if len(fields) == 7 and re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', fields[0]) and re.fullmatch(r'[0-9]{1,10}', fields[2]):
                accounts.setdefault(fields[2], fields[0])
        return accounts
    except OSError:
        return {}
    finally:
        if fd is not None:
            os.close(fd)


def user_label(value, accounts):
    if value in {'4294967295', '-1'}:
        return 'unset (no originating login recorded)'
    if not value:
        return 'not recorded'
    return f'{value} ({accounts[value]}; current local account mapping)' if value in accounts else value
