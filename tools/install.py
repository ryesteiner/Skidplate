"""Install Skidplate for the current user; never sudo, start services or alter auditd."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def safe_directory(path):
    """Reject symlink ancestors and foreign/writable installation directories."""
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise ValueError(f'Symlink installation path refused: {parent}')
    path.mkdir(mode=0o755, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError(f'Install directory must be owned by you and not group/world writable: {path}')


def literal_path(value):
    value = str(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('Installation paths cannot contain control characters')
    return value


def desktop_arg(value):
    value = literal_path(value).replace('%', '%%')
    # Exec quoting, then the desktop-entry string-unescape layer.
    value = ''.join('\\' + char if char in '\\"`$' else char for char in value)
    return '"' + value.replace('\\', '\\\\') + '"'


def unit_arg(value):
    # ExecStart uses ':' to disable environment expansion. '%' still needs escaping.
    return '"' + literal_path(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def write_file(path, text, mode=0o644):
    if path.is_symlink() or path.exists() and not path.is_file():
        raise ValueError(f'Non-regular installation target refused: {path}')
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(text)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def install(prefix, upgrade=False):
    if os.geteuid() == 0:
        raise ValueError('Run the installer as your normal user, never with sudo')
    prefix = Path(literal_path(prefix)).expanduser().absolute()
    if '..' in prefix.parts:
        raise ValueError('Installation prefix cannot contain parent traversal')
    safe_directory(prefix)
    for relative in ('bin', 'share', 'share/applications', 'share/systemd', 'share/systemd/user'):
        safe_directory(prefix / relative)
    target = prefix / 'share/skidplate'
    launcher = prefix / 'bin/skidplate'
    desktop = prefix / 'share/applications/skidplate.desktop'
    unit = prefix / 'share/systemd/user/skidplate.service'
    existing = any(path.exists() or path.is_symlink() for path in (target, launcher, desktop, unit))
    if existing and not upgrade:
        raise ValueError('Installation targets already exist; review them and use --upgrade to replace Skidplate files')
    if target.exists() or target.is_symlink():
        safe_directory(target)
        manifest = target / 'install-manifest.json'
        if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 8192:
            raise ValueError('Existing app lacks a regular Skidplate installation manifest')
        if json.loads(manifest.read_text()).get('application') != 'skidplate':
            raise ValueError('Existing app manifest does not identify Skidplate')
    for path in (launcher, desktop, unit):
        if path.is_symlink() or path.exists() and not path.is_file():
            raise ValueError(f'Unsafe install target: {path}')
        if path.exists() and path.stat().st_uid != os.getuid():
            raise ValueError(f'Install target is not owned by you: {path}')
    sources = [Path('run.py'), Path('LICENSE')]
    sources += sorted(Path('skidplate') / p.name for p in (ROOT / 'skidplate').glob('*.py'))
    sources += sorted(Path('assets') / p.name for p in (ROOT / 'assets').iterdir() if p.suffix in {'.css', '.svg'})
    for relative in sources:
        source = ROOT / relative
        if source.is_symlink() or source.parent.is_symlink() or not source.is_file():
            raise ValueError(f'Non-regular source refused: {source}')
    with tempfile.TemporaryDirectory(prefix='.skidplate-install-', dir=prefix / 'share') as temporary:
        staged = Path(temporary) / 'app'
        staged.mkdir()
        for relative in sources:
            destination = staged / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
            destination.chmod(0o644)
        (staged / 'install-manifest.json').write_text(json.dumps({'application': 'skidplate', 'format': 1,
            'files': [str(path) for path in sources]}, indent=2) + '\n')
        backup = None
        if target.exists():
            backup = target.with_name('skidplate.backup-' + str(time.time_ns()))
            target.rename(backup)
        staged.rename(target)
    entry = target / 'run.py'
    write_file(launcher, '#!/usr/bin/python3 -I\nimport runpy\nrunpy.run_path(' + repr(str(entry)) + ', run_name="__main__")\n', 0o755)
    icon = str(target / 'assets/shield.svg').replace('\\', '\\\\')
    write_file(desktop, '[Desktop Entry]\nType=Application\nName=Skidplate\nComment=Local Linux audit-log triage and process/network context\n'
        'Exec=/usr/bin/python3 -I ' + desktop_arg(entry) + '\nIcon=' + icon + '\nTerminal=false\nCategories=System;Security;\n')
    write_file(unit, '[Unit]\nDescription=Skidplate local security telemetry and tray monitor\nAfter=graphical-session-pre.target\nPartOf=graphical-session.target\n\n'
        '[Service]\nType=simple\nExecStart=:/usr/bin/python3 -I ' + unit_arg(entry) + ' --background\nUMask=0077\nNoNewPrivileges=yes\nRestart=on-failure\nRestartSec=10\n\n'
        '[Install]\nWantedBy=graphical-session.target\n')
    print(f'Installed app: {target}\nLauncher: {launcher}\nDesktop entry: {desktop}\nUser service: {unit}')
    if backup:
        print(f'Previous app retained for rollback: {backup}')
    print('No service was started, enabled or stopped. No audit configuration, log permissions or history changed.')
    return target, launcher, desktop, unit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, default=Path.home() / '.local', help='Install beneath this directory (default: ~/.local)')
    parser.add_argument('--upgrade', action='store_true', help='Replace an existing reviewed user installation; retain previous app payload')
    args = parser.parse_args()
    try:
        install(args.prefix, args.upgrade)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Skidplate installation failed: {exc}\nPartial files may remain; inspect before retrying.\n')


if __name__ == '__main__':
    main()
