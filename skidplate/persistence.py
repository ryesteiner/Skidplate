"""Persistence-location changes from captured audit metadata, never file contents."""
from dataclasses import dataclass
import posixpath
import re

PERSISTENCE_RULES = frozenset('persistence-' + name for name in
    ('systemd', 'cron', 'shell', 'autostart', 'ssh', 'loader', 'udev', 'pacman-hook'))
WATCH_KEYS = {'systemd_persistence', 'systemd', 'cron', 'init', 'udev', 'shell_profiles',
              'sentinel_persistence', 'sentinel_persistence_extra', 'sentinel_auth_policy',
              'sentinel_system_files', 'sentinel_pacman_config', 'sentinel_config_change'}
# Numeric ABI values verified against installed Linux UAPI syscall headers.
OPEN_CALLS = {'c000003e': {'2', '257', '437'}, '40000003': {'5', '295', '437'}, 'c00000b7': {'56', '437'}}
MUTATING = {
    'c000003e': set('1 18 20 76 77 82 85 86 87 88 90 91 92 93 94 260 263 264 265 266 268 316'.split()),
    '40000003': set('4 8 9 10 15 16 38 83 92 93 94 95 146 181 182 298 301 302 303 304 306 353'.split()),
    'c00000b7': set('35 36 37 38 45 46 52 53 54 55 64 66 68 276'.split()),
}
RISKY_ACTORS = ('/tmp/', '/var/tmp/', '/dev/shm/', '/home/', '/run/user/', '/memfd:', 'memfd:')


@dataclass(frozen=True)
class PersistenceChange:
    rule: str
    title: str
    target: str
    operation: str
    severity: str


def category(path):
    if re.match(r'^/(?:etc|usr/lib|usr/local/lib|run)/systemd/(?:system|user|system-generators|user-generators)/', path) or re.match(r'^/(?:home/[^/]+|root)/(?:\.config|\.local/share)/systemd/user/', path):
        return 'systemd', 'Systemd startup configuration changed'
    if path == '/etc/crontab' or re.match(r'^/etc/cron\.(?:d|hourly|daily|weekly|monthly)/', path) or path.startswith(('/var/spool/cron/', '/var/spool/at/')):
        return 'cron', 'Scheduled task configuration changed'
    if (path in {'/etc/profile', '/etc/bash.bashrc', '/etc/rc.local'} or
            path.startswith(('/etc/profile.d/', '/etc/zsh/')) or
            re.fullmatch(r'/(?:home/[^/]+|root)/\.(?:profile|bashrc|bash_profile|bash_login|zshenv|zprofile|zshrc)', path) or
            re.match(r'^/(?:home/[^/]+|root)/\.config/fish/(?:config\.fish$|conf\.d/.*\.fish$)', path)):
        return 'shell', 'Shell or login startup configuration changed'
    if path.endswith('.desktop') and (path.startswith('/etc/xdg/autostart/') or re.match(r'^/(?:home/[^/]+|root)/\.config/autostart/', path)):
        return 'autostart', 'Desktop autostart entry changed'
    if path == '/etc/ssh/sshrc' or re.fullmatch(r'/(?:home/[^/]+|root)/\.ssh/(?:authorized_keys2?|rc)', path):
        return 'ssh', 'SSH persistent access or startup file changed'
    if path in {'/etc/ld.so.preload', '/etc/ld.so.conf'} or path.startswith('/etc/ld.so.conf.d/'):
        return 'loader', 'Dynamic loader configuration changed'
    if path.endswith('.rules') and path.startswith(('/etc/udev/rules.d/', '/usr/lib/udev/rules.d/')):
        return 'udev', 'Device-triggered startup rule changed'
    if path.endswith('.hook') and path.startswith(('/etc/pacman.d/hooks/', '/usr/share/libalpm/hooks/')):
        return 'pacman-hook', 'Pacman transaction hook changed'
    return None


def changes(event):
    if 'SYSCALL' not in event.kinds or event.result.lower() not in {'yes', 'success', '1'}:
        return []
    arch, syscall = event.get('arch').lower(), event.get('syscall')
    watched = bool(set(event.get('key').split('\x01')) & WATCH_KEYS)
    if syscall not in MUTATING.get(arch, set()) and not (watched and syscall in OPEN_CALLS.get(arch, set())):
        return []
    rows = [row for row in event.records if row.kind == 'PATH']
    parents = {row.values.get('name', '') for row in rows if row.values.get('nametype') == 'PARENT' and row.values.get('name', '').startswith('/')}
    cwd = next((row.values.get('cwd', '') for row in event.records if row.kind == 'CWD'), '')
    found = {}
    # Prefer destination/create evidence over old rename names, one alert per mechanism/event.
    for row in sorted(rows, key=lambda row: row.values.get('nametype') != 'CREATE'):
        path, operation = row.values.get('name', ''), row.values.get('nametype', 'NORMAL')
        if operation == 'PARENT' or not path or path == '(null)' or len(path) > 4096:
            continue
        if not path.startswith('/'):
            if '/' not in path and parents:
                if len(parents) != 1:
                    continue
                parent = next(iter(parents))
            else:
                parent = cwd
            if not parent.startswith('/'):
                continue
            path = posixpath.join(parent, path)
        path = posixpath.normpath(path)
        match = category(path)
        if not match:
            continue
        name, title = match
        sensitive = name in {'ssh', 'loader'}
        suspicious = event.get('exe').startswith(RISKY_ACTORS)
        created = operation == 'CREATE' and not path.startswith(('/usr/lib/', '/usr/share/'))
        severity = 'high' if sensitive or suspicious or created else 'medium'
        label = operation if operation in {'CREATE', 'DELETE'} else 'WRITE-CAPABLE OPEN' if syscall in OPEN_CALLS.get(arch, set()) else 'MUTATION / ATTRIBUTE'
        found.setdefault(name, PersistenceChange('persistence-' + name, title.replace(' changed', ' write activity'), path, label, severity))
    return list(found.values())[:8]
