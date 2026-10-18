from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from skidplate.network import collect, NetworkSampler, attach_owners
from skidplate.widgets import cluster_layout
from skidplate.behavior import sequence_groups


def row(state='01', inode='100', remote='08080808:01BB', local='0100007F:1234'):
    return f'0: {local} {remote} {state} 0:0 0:0 0 1000 0 {inode} 1\n'


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'ns').mkdir(); (self.root / 'net').mkdir()
        (self.root / 'ns' / 'net').symlink_to('net:[123]')
        for table in ('tcp', 'tcp6', 'udp', 'udp6'):
            (self.root / 'net' / table).write_text('sl local_address rem_address st\n')

    def tearDown(self):
        self.temp.cleanup()

    def write(self, table, lines):
        (self.root / 'net' / table).write_text('sl local_address rem_address st\n' + lines)

    def test_active_states_udp_loopback_and_ipv6_are_counted_separately(self):
        self.write('tcp', row() + row('0A', '101') + row('06', '0') + row('02', '102') + row())
        self.write('udp', row('01', '200') + row('07', '201', '00000000:0000'))
        self.write('tcp6', row('01', '300', '00000000000000000000000001000000:01BB', '00000000000000000000000001000000:1234'))
        result = collect(root=self.root)
        self.assertTrue(result['complete'])
        self.assertEqual(result['tables'], 4)
        self.assertEqual((result['active'], result['tcp'], result['udp'], result['listening']), (3, 2, 1, 1))
        self.assertEqual(len(result['rows']), 7)
        self.assertEqual(result['rows'][-2]['uid'], '1000')
        self.assertTrue(any(r['remote'] == '[::1]:443' for r in result['rows']))

    def test_missing_and_malformed_tables_are_explicit_partial_not_complete_zero(self):
        self.write('tcp', row())
        (self.root / 'net' / 'udp6').unlink()
        self.write('udp', 'untrusted malformed row\n')
        result = collect(root=self.root)
        self.assertFalse(result['complete'])
        self.assertEqual(result['active'], 1)
        self.assertEqual(len(result['notes']), 2)

    def test_namespace_change_discards_counts_and_rows(self):
        self.write('tcp', row())
        with patch('skidplate.network.os.readlink', side_effect=['net:[123]', 'net:[456]']):
            result = collect(root=self.root)
        self.assertFalse(result['complete'])
        self.assertEqual(result['tables'], 0)
        self.assertEqual(result['active'], 0)
        self.assertEqual(result['rows'], [])

    def test_caps_keep_lower_bounds_and_report_partial_visibility(self):
        self.write('tcp', row(inode='1') + row(inode='2') + row(inode='3'))
        with patch('skidplate.network.MAX_ROWS', 2):
            result = collect(root=self.root)
        self.assertEqual(result['active'], 2)
        self.assertEqual(len(result['rows']), 2)
        self.assertFalse(result['complete'])

    def test_oversized_and_timed_out_tables_do_not_report_complete(self):
        (self.root / 'net' / 'tcp').write_bytes(b'x' * (1024 * 1024 + 1))
        self.assertFalse(collect(root=self.root)['complete'])
        ticks = iter([0, 3, 3, 3, 3])
        result = collect(root=self.root, clock=lambda: next(ticks))
        self.assertFalse(result['complete'])
        self.assertEqual(result['tables'], 0)

    def test_sampler_never_starts_parallel_workers_and_close_stops_requests(self):
        entered, release = threading.Event(), threading.Event()
        sampler = NetworkSampler()
        def fake():
            entered.set()
            release.wait(2)
            return {'fixture': True}
        with patch('skidplate.network.collect', side_effect=fake) as mocked, patch('skidplate.network.attach_owners'):
            sampler.request(force=True)
            self.assertTrue(entered.wait(1))
            sampler.request(force=True)
            release.set(); sampler.thread.join(1)
            self.assertEqual(mocked.call_count, 1)
            self.assertEqual(sampler.poll(), {'fixture': True})
            self.assertIsNone(sampler.poll())
            sampler.close(); sampler.request(force=True)
            self.assertEqual(mocked.call_count, 1)


class HolderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.result = {'rows': [{'inode': '100'}, {'inode': '0'}]}

    def tearDown(self):
        self.temp.cleanup()

    def process(self, pid, inode='100'):
        directory = self.root / str(pid)
        (directory / 'fd').mkdir(parents=True)
        (directory / 'exe').symlink_to('/usr/bin/example-app')
        (directory / 'stat').write_text(f'{pid} (example) ' + ' '.join(['S', '1'] + ['0'] * 17 + ['500']))
        (directory / 'fd' / '4').symlink_to(f'socket:[{inode}]')

    def test_shared_holders_have_pid_path_and_inode_zero_is_unknown(self):
        self.process(123); self.process(124)
        attach_owners(self.result, root=self.root)
        self.assertEqual({o['pid'] for o in self.result['rows'][0]['owners']}, {'123', '124'})
        self.assertEqual(self.result['rows'][0]['owners'][0]['exe'], '/usr/bin/example-app')
        self.assertEqual(self.result['rows'][1]['owners'], [])

    def test_changed_process_discards_holder_matches(self):
        self.process(123)
        with patch('skidplate.network.proc_identity', side_effect=[(500,1,'S','/usr/bin/example-app'),(501,1,'S','/usr/bin/example-app')]):
            attach_owners(self.result, root=self.root)
        self.assertEqual(self.result['rows'][0]['owners'], [])
        self.assertTrue(self.result['owner_notes'])

    def test_closed_descriptor_is_not_attributed(self):
        import os
        self.process(123)
        original, seen = os.readlink, []
        def link(path):
            if str(path).endswith('/fd/4'):
                seen.append(1)
                return 'socket:[100]' if len(seen) == 1 else 'socket:[200]'
            return original(path)
        with patch('skidplate.network.os.readlink', side_effect=link):
            attach_owners(self.result, root=self.root)
        self.assertEqual(self.result['rows'][0]['owners'], [])

    def test_permission_gaps_and_holder_caps_are_explicit(self):
        self.process(123)
        with patch('skidplate.network.os.open', side_effect=PermissionError):
            attach_owners(self.result, root=self.root)
        self.assertEqual(self.result['rows'][0]['owners'], [])
        self.assertTrue(self.result['owner_notes'])
        for pid in range(124, 133):
            self.process(pid)
        attach_owners(self.result, root=self.root)
        self.assertEqual(len(self.result['rows'][0]['owners']), 8)
        self.assertIn('limit', ' '.join(self.result['owner_notes']))

    def test_symlink_pid_and_unmatched_inode_do_not_create_attribution(self):
        self.process(123, '999')
        (self.root / '124').symlink_to(self.root / '123')
        attach_owners(self.result, root=self.root)
        self.assertEqual(self.result['rows'][0]['owners'], [])


class InstrumentTests(unittest.TestCase):
    def test_gauges_fit_and_primary_is_larger_across_layouts(self):
        for width in (280, 400, 480, 759, 760, 1180, 2000):
            for percent in (80, 100, 120):
                for focus in ('network', 'attention', 'behavior'):
                    gauges, baseline, height = cluster_layout(width, percent, focus)
                    primary = next(g for g in gauges if g[0] == focus)
                    for name, x, y, radius in gauges:
                        self.assertGreaterEqual(x - radius - 8, 0)
                        self.assertLessEqual(x + radius + 8, width)
                        self.assertGreaterEqual(y - radius - 8, 0)
                        self.assertLess(y + radius + 8, height)
                        if name != focus:
                            self.assertLess(radius, primary[3])
                    for index, (_, x, y, radius) in enumerate(gauges):
                        for _, other_x, other_y, other_r in gauges[index+1:]:
                            self.assertGreaterEqual(((x-other_x)**2 + (y-other_y)**2)**.5, radius + other_r + 16)
                    self.assertLess(baseline + 30, height)

    def test_behavior_gauge_uses_live_group_count_not_occurrences_or_review_status(self):
        now = 100000
        rows = [(1, now, 'behavior-network'), (2, now, 'behavior-persistence'),
                (3, now - 86401, 'auth-success-after-failures'), (4, now, 'root-temp-exec'),
                (5, now + 100, 'behavior-network')]
        stats = {n: (900, now, '', '', n == 2) for n in range(1, 6)}
        groups, live = sequence_groups(rows, stats, now)
        self.assertEqual([r[0] for r in groups], [1, 2, 3, 5])
        self.assertEqual([r[0] for r in live], [1])
