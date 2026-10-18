from pathlib import Path
import tempfile
import time
import unittest

from skidplate.core import Detector, Event, Store, parse_line
from skidplate.persistence import changes, category
from skidplate.behavior import behavior_groups
from tools.build_persistence_profile import build


def event(target, *, syscall='257', key='sentinel_persistence', success='yes', exe='/usr/bin/editor',
          operation='NORMAL', serial=1, timestamp=None, cwd=None, parent=None):
    ts = time.time() if timestamp is None else timestamp
    body = f'arch=c000003e syscall={syscall} success={success} pid=123 ppid=1 auid=1000 ses=7 uid=1000 euid=1000 exe="{exe}" key="{key}"'
    rows = [parse_line(f'type=SYSCALL msg=audit({ts:.3f}:{serial}): {body}'),
            parse_line(f'type=PATH msg=audit({ts:.3f}:{serial}): name="{target}" nametype={operation}')]
    if cwd:
        rows.append(parse_line(f'type=CWD msg=audit({ts:.3f}:{serial}): cwd="{cwd}"'))
    if parent:
        rows.append(parse_line(f'type=PATH msg=audit({ts:.3f}:{serial}): name="{parent}" nametype=PARENT'))
    return Event(rows)


class PersistenceTests(unittest.TestCase):
    def test_categories_and_priority(self):
        examples = {'/etc/systemd/system/demo.service': 'systemd', '/home/demo/.config/systemd/user/demo.timer': 'systemd',
            '/etc/cron.d/demo': 'cron', '/home/demo/.bashrc': 'shell', '/home/demo/.config/autostart/demo.desktop': 'autostart',
            '/home/demo/.ssh/authorized_keys': 'ssh', '/etc/ld.so.preload': 'loader',
            '/etc/udev/rules.d/demo.rules': 'udev', '/etc/pacman.d/hooks/demo.hook': 'pacman-hook'}
        for target, name in examples.items():
            match = changes(event(target))[0]
            self.assertEqual(match.rule, 'persistence-' + name)
            self.assertEqual(match.severity, 'high' if name in {'ssh', 'loader'} else 'medium')
        self.assertEqual(changes(event('/etc/systemd/system/demo.service', operation='CREATE'))[0].severity, 'high')
        self.assertEqual(changes(event('/usr/lib/systemd/system/demo.service', operation='CREATE', exe='/usr/bin/pacman'))[0].severity, 'medium')
        self.assertEqual(changes(event('/home/demo/.bashrc', exe='/tmp/tool'))[0].severity, 'high')

    def test_failed_read_exec_and_unwatched_open_do_not_become_typed_changes(self):
        for extra in ({'success': 'no'}, {'syscall': '0'}, {'syscall': '59'}, {'key': 'unrelated-key'}):
            self.assertEqual(changes(event('/etc/ld.so.preload', **extra)), [])
        self.assertEqual(changes(event('/etc/ld.so.preload', key='unrelated-key', syscall='82'))[0].rule, 'persistence-loader')
        self.assertIsNone(category('/home/demo/.bashrc.backup'))
        self.assertEqual(changes(event('/tmp/not-a-persistence-file')), [])

    def test_parent_basename_and_cwd_resolution_keep_only_target_metadata(self):
        match = changes(event('demo.service', parent='/etc/systemd/system'))[0]
        self.assertEqual(match.target, '/etc/systemd/system/demo.service')
        saved = event('.bashrc', cwd='/home/demo').summary()
        self.assertNotIn('cwd', saved)
        self.assertEqual(saved['persistence'][0]['target'], '/home/demo/.bashrc')
        self.assertEqual(changes(event('demo.service')), [])
        ambiguous = event('demo.service', parent='/etc/systemd/system', cwd='/etc/systemd/system')
        ambiguous.records.append(parse_line(f'type=PATH msg=audit({ambiguous.timestamp:.3f}:1): name="/tmp" nametype=PARENT'))
        self.assertEqual(changes(ambiguous), [])

    def test_specific_alert_replaces_generic_and_preserves_context_snooze_precision(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp))
            detector = Detector(store)
            first = event('.bashrc', cwd='/home/one', key='sentinel_config_change')
            detector.process(first)
            second = event('.bashrc', cwd='/home/two', key='sentinel_config_change', serial=2)
            detector.process(second)
            rows = store.rows(alerts=True)
            self.assertEqual([row[2] for row in rows], ['persistence-shell', 'persistence-shell'])
            self.assertNotEqual(rows[0][7], rows[1][7])
            store.db.close()

    def test_user_temporary_execution_then_persistence_and_masquerading(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp)); detector = Detector(store)
            now = time.time()
            origin = event('/tmp/helper', syscall='59', key='sentinel_risky_exec', exe='/tmp/helper', timestamp=now)
            detector.process(origin, now=now)
            changed = event('/home/demo/.config/autostart/demo.desktop', exe='/tmp/helper', timestamp=now+2, serial=2)
            matches = detector.process(changed, now=now+2)
            self.assertIn('behavior-user-persistence', {row.rule for row in matches})
            masked = event('/tmp/sshd', syscall='59', key='sentinel_risky_exec', exe='/tmp/sshd', timestamp=now+3, serial=3)
            self.assertIn('process-masquerade', {row.rule for row in detector.process(masked, now=now+3)})
            groups, live = behavior_groups(store.rows(alerts=True), store.alert_stats(), now+3)
            self.assertTrue(any(row[2] == 'persistence-autostart' for row in live))
            self.assertTrue(any(row[2] == 'behavior-user-persistence' for row in groups))
            store.db.close()

    def test_profile_is_additive_skips_missing_and_staged_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'home/demo').mkdir(parents=True)
            (root / 'home/demo/.bashrc').write_text('fixture')
            (root / 'etc/systemd/system').mkdir(parents=True)
            (root / 'tmp').mkdir()
            lines, skipped = build(root, home='/home/demo', prior='-a always,exit -F arch=b64 -F dir=/etc -F perm=wa -k prior')
            text = '\n'.join(lines)
            self.assertIn('-F path=/home/demo/.bashrc', text)
            self.assertIn('-F dir=/tmp -F perm=x', text)
            self.assertNotIn('-F dir=/etc/systemd/system', text)
            self.assertNotIn('-D', text)
            self.assertNotIn('-e 2', text)
            self.assertTrue(any(path.endswith('.ssh') for path, _ in skipped))
            self.assertFalse((root / 'home/demo/.ssh').exists())
            with self.assertRaises(ValueError):
                build(root, home='/home/demo bad')
