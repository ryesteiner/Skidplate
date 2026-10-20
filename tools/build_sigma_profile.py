"""Prepare an additive x86_64 auditd draft; never elevate, install or load it.

Targeted executable watches limit new argv collection. Arbitrary executable
names (notably miners) need broader exec coverage, deliberately opt-in. Existing
live/persistent rules must be checked for first-match keys and duplication.
"""
import argparse
import os
from pathlib import Path
import platform


C2_TOOLS = ('wget', 'curl', 'base64', 'nc', 'netcat', 'ncat', 'ss', 'netstat',
            'ssh', 'scp', 'sftp', 'ftp', 'socat', 'wireshark', 'tshark',
            'rawshark', 'rdesktop', 'wlfreerdp', 'xfreerdp', 'nmap')
ARGUMENT_TOOLS = ('sysctl', 'iptables', 'ip6tables', 'firewall-cmd', 'ufw', 'nft',
                  'chattr', 'chmod', 'cp', 'grep', 'touch', 'truncate', 'dd', 'xmrig')


def build(root=Path('/'), all_exec=False):
    """Fixed tool paths only; absent/symlink executables are explicitly skipped."""
    rules, skipped = [], []
    for name in dict.fromkeys(C2_TOOLS + ARGUMENT_TOOLS):
        relative = '/usr/bin/' + name
        path = root / relative.lstrip('/')
        if path.is_symlink() or not path.is_file():
            skipped.append(relative)
            continue
        key = 'susp_activity' if name in C2_TOOLS else 'sentinel_sigma_exec'
        for arch in ('b64', 'b32'):
            # Prepend live overlays so generic exec rules cannot hide this key.
            rules.append(f'-A always,exit -F arch={arch} -S execve,execveat -F path={relative} -F perm=x -k {key}')
    for arch in ('b64', 'b32'):
        # Numeric syscall filters, not argv string filters. No success filter:
        # attempted and denied actions are useful and remain labeled as such.
        for action in (4, 5, 6):
            rules.append(f'-A always,exit -F arch={arch} -S syslog -F a0={action} -k sentinel_sigma_syslog')
        rules.append(f'-A always,exit -F arch={arch} -S personality -F a0&=0x40000 -k sentinel_sigma_aslr')
        if all_exec:
            rules.append(f'-a always,exit -F arch={arch} -S execve,execveat -k sentinel_sigma_all_exec')
    return rules, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).resolve().parents[1] / 'build/sigma-audit')
    parser.add_argument('--all-exec', action='store_true', help='Opt in to HIGH VOLUME argv collection for every executable/user; review privacy/disk/backlog first')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Generate as your normal user, never sudo')
    if platform.machine() != 'x86_64':
        parser.error('Draft supports x86_64 b64/b32 only; review other ABIs separately')
    rules, skipped = build(all_exec=args.all_exec)
    directory = args.output_dir.absolute()
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        parser.error('Symlink output directories refused')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ('35-skidplate-sigma.rules', '35-skidplate-sigma.rollback'):
        if (directory / name).exists() or (directory / name).is_symlink():
            parser.error('Output already exists; choose a fresh --output-dir to preserve previous drafts')
    header = ('# DRAFT ONLY: read docs/SIGMA-ARGUMENTS.md before activation.\n'
              '# No reset, suppression, immutable, backlog, failure or rate changes.\n'
              '# Adds raw argv to root-owned audit logs; Skidplate saves no argv.\n'
              '# Not a guarantee of collection: ordering, existing watches and losses matter.\n'
              '# Skipped absent/symlink executables: ' + ', '.join(skipped) + '\n')
    with (directory / '35-skidplate-sigma.rules').open('x') as stream:
        stream.write(header + '\n'.join(rules) + '\n')
    with (directory / '35-skidplate-sigma.rollback').open('x') as stream:
        stream.write('# Exact overlay removals; never auditctl -D.\n' + '\n'.join(
            line.replace('-A always,exit', '-d always,exit', 1).replace('-a always,exit', '-d always,exit', 1)
            for line in reversed(rules)) + '\n')
    print(f'Prepared {len(rules)} rules and exact removals in {directory}; skipped {len(skipped)} tools.')
    print('No host configuration changed. Review first-match keys, duplicates, syscall support and argv privacy before administrator installation.')


if __name__ == '__main__':
    main()
