"""Synthetic local audit behavior, grouping and investigation regressions."""
import ipaddress
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from skidplate.core import Detector, Event, Store, parse_line
from skidplate.behavior import BehaviorCorrelator, IMPORTANT_RULES


class BehaviorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name))
        self.detector = Detector(self.store)
        self.now = time.time()
        self.serial = 0

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def event(self, offset=0, kind='SYSCALL', body='', node='local'):
        self.serial += 1
        return Event([parse_line(f'node={node} type={kind} msg=audit({self.now+offset:.3f}:{self.serial}): {body}')])

    def subject(self, **changes):
        values = dict(arch='c000003e', syscall='59', success='yes', pid='123', ppid='12',
                      auid='1000', uid='1000', euid='0', ses='7', exe='/home/demo/example')
        values.update(changes)
        return ' '.join(f'{key}="{value}"' for key, value in values.items() if value is not None)

    def process(self, event, historical=False):
        return self.detector.process(event, now=max(self.now, event.timestamp), historical=historical)

    def connect(self, offset=2, address='8.8.8.8', pending=False, **changes):
        event = self.event(offset, body=self.subject(syscall='42', success='no' if pending else 'yes',
                            exit='-115' if pending else '0', **changes))
        raw = b'\x02\x00\x01\xbb' + ipaddress.ip_address(address).packed + b'\x00' * 8
        event.records.append(parse_line(f'type=SOCKADDR msg=audit({event.timestamp:.3f}:{self.serial}): saddr={raw.hex()}'))
        return event

    def test_same_process_root_origin_to_persistence_and_linked_events(self):
        origin = self.event(body=self.subject())
        self.process(origin)
        follow = self.event(2, body=self.subject(syscall='257', key='systemd_persistence'))
        alerts = self.process(follow)
        chain = next(alert for alert in alerts if alert.rule == 'behavior-persistence')
        self.assertIn(origin.identity, chain.detail)
        self.assertIn('PID=123', chain.detail)
        saved = next(row for row in self.store.rows(alerts=True) if row[2] == chain.rule)
        events, limits = self.store.investigation(saved[0])
        self.assertEqual({row[0] for row in events}, {origin.identity, follow.identity})
        self.assertIn('not proof', limits)

    def test_public_connect_and_pending_are_precisely_labelled(self):
        self.process(self.event(body=self.subject()))
        alerts = self.process(self.connect(pending=True))
        match = next(alert for alert in alerts if alert.rule == 'behavior-network')
        self.assertIn('completion unknown', match.detail)
        self.assertIn('not identification', match.detail)

    def test_mismatched_missing_system_id_expired_failed_and_private_do_not_correlate(self):
        for changes in ({'pid': '124'}, {'ses': '8'}, {'auid': '1001'}, {'exe': '/home/demo/other'},
                        {'ses': None}, {'ses': '4294967295'}, {'auid': '0'}):
            self.detector.reset_correlation()
            self.process(self.event(body=self.subject()))
            alerts = self.process(self.connect(**changes))
            self.assertFalse(any(alert.rule.startswith('behavior-') for alert in alerts), changes)
        for offset, address in ((301, '8.8.8.8'), (2, '127.0.0.1'), (2, '192.168.1.1')):
            self.detector.reset_correlation()
            self.process(self.event(body=self.subject()))
            self.assertFalse(any(a.rule == 'behavior-network' for a in self.process(self.connect(offset, address))))
        self.detector.reset_correlation()
        self.process(self.event(body=self.subject()))
        failed = self.event(2, body=self.subject(syscall='257', success='no', key='systemd_persistence'))
        self.assertFalse(any(a.rule == 'behavior-persistence' for a in self.process(failed)))

    def test_host_history_order_new_exec_and_daemon_boundary(self):
        self.process(self.event(body=self.subject(), node='other-host'))
        self.assertFalse(any(a.rule == 'behavior-network' for a in self.process(self.connect())))
        self.detector.reset_correlation()
        self.process(self.event(body=self.subject()), historical=True)
        self.assertFalse(any(a.rule == 'behavior-network' for a in self.process(self.connect())))
        self.detector.reset_correlation()
        self.process(self.event(3, body=self.subject()))
        self.assertFalse(any(a.rule == 'behavior-network' for a in self.process(self.connect(2))))
        self.detector.reset_correlation()
        self.process(self.event(body=self.subject()))
        self.process(self.event(1, body=self.subject(exe='/usr/bin/trusted')))
        self.assertFalse(any(a.rule == 'behavior-network' for a in self.process(self.connect())))
        self.detector.reset_correlation()
        self.process(self.event(body=self.subject()))
        self.process(self.event(1, kind='DAEMON_START'))
        self.assertFalse(any(a.rule == 'behavior-network' for a in self.process(self.connect())))

    def test_authentication_success_after_failures_requires_matching_context(self):
        def auth(offset, result, address='192.0.2.1', node='local'):
            return self.event(offset, 'USER_AUTH', f'acct="demo" addr="{address}" res={result}', node)
        for i in range(5): self.process(auth(i, 'failed'))
        other = self.process(auth(5, 'success', '192.0.2.2'))
        self.assertFalse(any(a.rule == 'auth-success-after-failures' for a in other))
        success = self.process(auth(6, 'success'))
        self.assertTrue(any(a.rule == 'auth-success-after-failures' for a in success))
        self.assertFalse(any(a.rule == 'auth-success-after-failures' for a in self.process(auth(7, 'success'))))
        self.assertFalse(any(a.rule == 'auth-burst' for a in self.process(auth(8, 'failed'))))

    def test_repeated_policy_events_group_with_counts_and_keep_summaries(self):
        def policy(offset, pid):
            return self.event(offset, 'AVC', f'apparmor="DENIED" profile="firefox" operation="open" name="/example" pid={pid}')
        first = policy(0, 1)
        self.process(first)
        identity = self.store.rows(alerts=True)[0][0]
        self.store.db.execute('UPDATE alerts SET acknowledged=1'); self.store.db.commit()
        self.assertEqual(self.process(policy(1, 2)), [])
        self.process(policy(61, 3))
        rows = self.store.rows(alerts=True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], identity)
        self.assertEqual(rows[0][6], 0)
        self.assertEqual(self.store.alert_stats()[identity][0], 3)
        self.assertEqual(self.store.alert_stats()[identity][2], first.identity)
        self.assertEqual(len(self.store.rows()), 3)
        self.process(policy(3601, 4))
        self.assertEqual(len(self.store.rows(alerts=True)), 2)
        history = policy(3602, 5)
        self.process(history, historical=True)
        self.assertEqual(len(self.store.rows(alerts=True)), 3)

    def test_duplicate_event_never_increments_group_and_incomplete_metadata_is_not_inferred(self):
        event = self.event(kind='AVC', body='apparmor="DENIED" name="/example"')
        self.process(event); self.process(event)
        identity = self.store.rows(alerts=True)[0][0]
        self.assertEqual(self.store.alert_stats()[identity][0], 1)
        linked, explanation = self.store.investigation(identity)
        self.assertEqual(len(linked), 1)
        self.assertIn('incomplete', explanation)

    def test_database_failure_does_not_advance_cooldown(self):
        event = self.event(kind='DAEMON_END')
        with patch.object(self.store, 'alert', side_effect=sqlite3.OperationalError('simulated')):
            with self.assertRaises(sqlite3.Error): self.process(event)
        self.assertEqual(self.detector.cooldown, {})
        self.store.db.rollback()
        self.detector.reset_correlation()
        self.assertTrue(self.process(event))

    def test_focus_is_a_view_and_notification_policy_not_rule_muting(self):
        self.assertIn('behavior-network', IMPORTANT_RULES)
        self.assertNotIn('policy-denial', IMPORTANT_RULES)
        alerts = self.process(self.event(kind='AVC', body='apparmor="DENIED" name="/example"'))
        self.assertEqual(alerts[0].rule, 'policy-denial')
        self.assertEqual(len(self.store.rows(alerts=True)), 1)


if __name__ == '__main__':
    unittest.main()
