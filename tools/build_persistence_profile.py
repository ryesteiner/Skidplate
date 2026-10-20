"""Print additive persistence watches for review; never install, load or create targets."""
from pathlib import Path
import re
import argparse
import os
import platform

SYSTEM = ('/etc/systemd/system', '/etc/systemd/user', '/usr/lib/systemd/system',
          '/usr/lib/systemd/user', '/etc/systemd/system-generators', '/etc/systemd/user-generators',
          '/usr/lib/systemd/system-generators', '/usr/lib/systemd/user-generators',
          '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly',
          '/etc/crontab', '/var/spool/cron', '/var/spool/at', '/etc/profile', '/etc/profile.d',
          '/etc/bash.bashrc', '/etc/zsh', '/etc/rc.local', '/etc/ssh', '/etc/ld.so.preload',
          '/etc/ld.so.conf', '/etc/ld.so.conf.d', '/etc/udev/rules.d', '/usr/lib/udev/rules.d',
          '/etc/pacman.d/hooks', '/usr/share/libalpm/hooks', '/etc/xdg/autostart')
USER = ('.config/systemd/user', '.local/share/systemd/user', '.config/autostart', '.config/fish',
        '.ssh', '.profile', '.bashrc', '.bash_profile', '.bash_login', '.zshenv', '.zprofile', '.zshrc')


def build(root=Path('/'), home=None, prior=''):
    home = str(Path.home()) if home is None else str(home)
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', home) or '..' in Path(home).parts:
        raise ValueError('Use a simple absolute home path without whitespace or parent traversal')
    if len(prior) > 65536:
        raise ValueError('Prior collection profile too large')
    # This avoids duplication against the staged profile only, not unqueried kernel rules.
    covered = re.findall(r'-F (dir|path)=([^\s]+)', prior)
    rules, skipped = [], []
    for target in SYSTEM + tuple(home + '/' + name for name in USER):
        if any(target == path or kind == 'dir' and target.startswith(path.rstrip('/') + '/') for kind, path in covered):
            skipped.append((target, 'covered by staged 60 profile; live activation unverified'))
            continue
        path = root / target.lstrip('/')
        try:
            info = path.lstat()
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError('not a regular file/directory')
        except (OSError, ValueError):
            skipped.append((target, 'missing, unreadable or symlink; no target created'))
            continue
        field = 'dir' if path.is_dir() else 'path'
        for arch in ('b64', 'b32'):
            rules.append(f'-a always,exit -F arch={arch} -F {field}={target} -F perm=wa -k sentinel_persistence_extra')
    for target in ('/tmp', '/var/tmp', '/dev/shm'):
        path = root / target.lstrip('/')
        if not path.is_dir() or path.is_symlink():
            skipped.append((target, 'risky binary-exec collection path unavailable'))
            continue
        for arch in ('b64', 'b32'):
            rules.append(f'-a always,exit -F arch={arch} -F dir={target} -F perm=x -k sentinel_risky_exec')
    return rules, skipped


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', default=str(Path.home()))
    parser.add_argument('--prior', type=Path, help='Optional reviewed base draft; overlap check is not live kernel verification')
    args = parser.parse_args()
    if os.geteuid() == 0 or platform.machine() != 'x86_64':
        parser.error('Generate as an ordinary user on x86_64 Arch Linux; review portability before loading elsewhere')
    prior = args.prior.read_text() if args.prior else ''
    rules, skipped = build(home=args.home, prior=prior)
    print('# Skidplate supplemental persistence watches for x86_64 Arch Linux.')
    print('# Review before root-owned installation; no reset, ignore-errors, immutable or panic directives.')
    print('# Existing collection remains installed. This draft does not verify live kernel coverage.')
    for path, reason in skipped:
        print(f'# Skipped {path}: {reason}')
    print('\n'.join(rules))
