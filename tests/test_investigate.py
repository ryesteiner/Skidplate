import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from skidplate.core import Event, Store, parse_line
from skidplate.investigate import endpoint, snapshot


def event(serial=1, timestamp=1000):
    return Event([parse_line(f'type=SYSCALL msg=audit({timestamp}:'+str(serial)+'): pid=123 ppid=20 auid=1000 ses=7 exe="/usr/bin/tool"')])


class CounterTests(unittest.TestCase):
    def test_counter_survives_retention_restart_duplicate_and_rollback(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / 'state'
            store = Store(directory)
            self.assertEqual(int(store.get('events_processed')), 0)
            self.assertTrue(store.event(event()))
            store.db.commit()
            self.assertFalse(store.event(event()))
            self.assertEqual(int(store.get('events_processed')), 1)
            store.event(event(2))
            store.db.rollback()
            self.assertEqual(int(store.get('events_processed')), 1)
            store.retain(now=1000 + 8 * 86400)
            self.assertEqual(store.rows(), [])
            store.db.close()
            store = Store(directory)
            self.assertEqual(int(store.get('events_processed')), 1)
            store.event(event(3)); store.db.commit()
            self.assertEqual(int(store.get('events_processed')), 2)
            # Simulate an upgrade from a DB without counters, with saved history.
            store.db.execute("DELETE FROM meta WHERE key IN ('events_processed','counter_started')")
            store.db.commit(); store.db.close()
            store = Store(directory)
            self.assertEqual(int(store.get('events_processed')), 1)
            self.assertTrue(store.get('counter_started'))
            store.db.close()

    def test_exact_pivots_search_all_retained_rows_and_reject_field_injection(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / 'state')
            for index in range(520):
                row = event(index, 1000 + index)
                row.records[0].values['exe'] = '/usr/bin/old-tool' if index == 0 else '/usr/bin/other'
                store.event(row)
            store.db.commit()
            self.assertEqual(len(store.rows()), 500)
            self.assertEqual(len(store.related('exe', '/usr/bin/old-tool')), 1)
            self.assertEqual(store.related('pid OR 1=1', '123'), [])
            self.assertEqual(store.related('exe', '/usr/bin/old'), [])
            self.assertEqual(len(store.related('pid', '123')), 200)
            store.db.close()

    def test_connect_summary_persists_endpoint_only_for_connect_syscall(self):
        call = parse_line('type=SYSCALL msg=audit(1000:1): arch=c000003e syscall=42 success=no')
        address = parse_line('type=SOCKADDR msg=audit(1000:1): saddr=020001BB080808080000000000000000')
        data = Event([call, address]).summary()
        self.assertEqual(data['connections'], [{'ip': '8.8.8.8', 'port': 443}])
        call.values['syscall'] = '49'
        self.assertEqual(Event([call, address]).summary()['connections'], [])


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.pid = self.root / '123'
        (self.pid / 'fd').mkdir(parents=True)
        (self.pid / 'net').mkdir()
        tail = ['S', '20'] + ['0'] * 17 + ['500'] + ['0'] * 20
        (self.pid / 'stat').write_text('123 (a tricky ) process) ' + ' '.join(tail))
        (self.pid / 'exe').symlink_to('/usr/bin/tool')
        (self.pid / 'loginuid').write_text('1000\n')
        (self.pid / 'sessionid').write_text('7\n')
        (self.pid / 'status').write_text('Uid:\t1000\t1000\t1000\t1000\n')
        (self.root / 'stat').write_text('btime 1000\n')
        (self.pid / 'fd' / '4').symlink_to('socket:[12345]')
        for table in ('tcp', 'tcp6', 'udp', 'udp6'):
            (self.pid / 'net' / table).write_text('header\n')
        (self.pid / 'net' / 'tcp').write_text('header\n'
            '0: 0100007F:1234 08080808:01BB 01 0:0 0:0 0 1000 0 12345 1\n'
            '1: 0100007F:9999 01010101:0050 01 0:0 0:0 0 1000 0 99999 1\n')
        self.summary = {'pid': '123', 'exe': '/usr/bin/tool', 'auid': '1000', 'session': '7', 'node': 'local'}

    def tearDown(self):
        self.temp.cleanup()

    def inspect(self, summary=None, when=1010):
        with patch('skidplate.investigate.os.sysconf', return_value=100):
            return snapshot(self.summary if summary is None else summary, when, root=self.root, now=1020)

    def test_socket_inode_association_excludes_other_namespace_sockets(self):
        result = self.inspect()
        self.assertTrue(result['matched'], result)
        self.assertEqual(result['process']['start'], 1005)
        self.assertEqual(len(result['connections']), 1)
        self.assertEqual(result['connections'][0]['remote'], '8.8.8.8:443')
        self.assertEqual(result['connections'][0]['state'], 'ESTABLISHED')

    def test_rejects_stale_wrong_host_missing_session_exe_and_path_pids(self):
        self.assertFalse(self.inspect(when=1000)['matched'])
        for key, value in [('node', 'remote-host'), ('session', ''), ('session', '8'),
                           ('exe', '/usr/bin/other'), ('pid', '../123'), ('auid', '4294967295')]:
            result = self.inspect(dict(self.summary, **{key: value}))
            self.assertFalse(result['matched'], result)
            self.assertEqual(result['connections'], [])

    def test_permission_gaps_are_visible_and_not_a_clean_network_verdict(self):
        with patch('skidplate.investigate.os.scandir', side_effect=PermissionError):
            result = self.inspect()
        self.assertTrue(result['matched'])
        self.assertEqual(result['connections'], [])
        self.assertIn('visibility unknown', ' '.join(result['notes']))

    def test_process_change_discards_collected_connections(self):
        first = (500, 20, 'S', '/usr/bin/tool')
        with patch('skidplate.investigate.proc_identity', side_effect=[first, (501, 20, 'S', '/usr/bin/tool')]):
            result = self.inspect()
        self.assertFalse(result['matched'])
        self.assertEqual(result['connections'], [])
        self.assertEqual(result['process'], {})

    def test_scheduler_state_changes_do_not_reject_same_process(self):
        with patch('skidplate.investigate.proc_identity', side_effect=[
                (500, 20, 'S', '/usr/bin/tool'), (500, 20, 'R', '/usr/bin/tool')]):
            self.assertTrue(self.inspect()['matched'])

    def test_ipv6_and_bad_endpoints(self):
        self.assertEqual(endpoint('00000000000000000000000001000000:01BB'), '[::1]:443')
        with self.assertRaises(ValueError):
            endpoint('bad:443')
