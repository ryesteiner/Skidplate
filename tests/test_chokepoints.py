"""Synthetic audit inputs only: no scans, root commands or real connections."""
import ipaddress
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest

from skidplate.core import Detector, Event, Store, parse_line
from skidplate.evidence import local_accounts, operation, targets, user_label


class ChokepointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'state')
        self.detector = Detector(self.store)
        self.now = time.time()
        self.serial = 0

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def event(self, offset=0, kind='SYSCALL', extra='', **changes):
        self.serial += 1
        fields = dict(arch='c000003e', syscall='59', success='yes', pid='123', ppid='12',
                      auid='1000', uid='1000', euid='1000', ses='7', exe='/usr/bin/tool') if kind == 'SYSCALL' else {}
        fields.update(changes)
        text = ' '.join(f'{key}="{value}"' for key, value in fields.items() if value is not None)
        return Event([parse_line(f'type={kind} msg=audit({self.now + offset:.3f}:{self.serial}): {text} {extra}')])

    def process(self, event, historical=False):
        return self.detector.process(event, now=max(self.now, event.timestamp), historical=historical)

    def connect(self, offset, ip='8.8.8.8', port=443, **changes):
        event = self.event(offset, syscall='42', **changes)
        address = ipaddress.ip_address(ip)
        raw = ((b'\x02\x00' + port.to_bytes(2, 'big') + address.packed + b'\x00' * 8)
               if address.version == 4 else (b'\x0a\x00' + port.to_bytes(2, 'big') + b'\x00' * 4 + address.packed + b'\x00' * 4))
        event.records.append(parse_line(f'type=SOCKADDR msg=audit({event.timestamp:.3f}:{self.serial}): saddr={raw.hex()}'))
        return event

    def rules(self, event, **options):
        return {alert.rule: alert for alert in self.process(event, **options)}

    def test_sudo_launch_auth_and_authorization_are_distinct_from_command_execution(self):
        self.assertIn('privilege-tool', self.rules(self.event(exe='/usr/bin/sudo')))
        auth = self.event(1, '1100', exe='/usr/bin/sudo', acct='demo', res='failed', auid='1000')
        self.assertIn('sudo-authentication', self.rules(auth))
        authorization = self.event(2, '1123', extra='cmd="secret password"', exe='/usr/bin/sudo', res='success', auid='1000')
        alert = self.rules(authorization)['sudo-authorization']
        self.assertIn('Authorization outcome only', alert.detail)
        self.assertNotIn('secret', json.dumps(authorization.summary()))
        self.assertNotIn('sudo-authentication', self.rules(self.event(3, 'USER_AUTH', exe='/tmp/sudo', res='failed')))

    def test_uid_selector_validated_for_each_abi_and_never_trusts_supplied_class(self):
        for arch, call, arg in [('c000003e', '105', 'a0'), ('40000003', '213', 'a0'),
                               ('c00000b7', '147', 'a1')]:
            with self.subTest(arch=arch):
                event = self.event(arch=arch, syscall=call, extra=f'{arg}=0', exe='/tmp/tool')
                self.assertEqual(event.get('requested_euid'), '0')
                self.assertEqual(self.rules(event)['privilege-root-request'].severity, 'high')
                self.assertNotIn(arg, event.records[0].values)
        fake = self.event(syscall='1', extra='requested_euid=0 uid_operation=setuid')
        self.assertEqual(fake.get('requested_euid'), '')
        self.assertNotIn('privilege-root-request', self.rules(fake))
        for extra in ('a0=ffffffff', 'a0=10000000000000000', 'a0=badvalue'):
            self.assertNotIn('privilege-root-request', self.rules(self.event(syscall='105', extra=extra)))
        self.assertNotIn('privilege-root-request', self.rules(self.event(syscall='105', extra='a0=0', auid='4294967295')))
        denied = self.rules(self.event(syscall='105', extra='a0=0', success='no', exe='/tmp/tool'))['privilege-root-request']
        self.assertEqual(denied.severity, 'medium')

    def test_observed_root_transition_requires_previous_successful_exec_and_same_identity(self):
        self.process(self.event(exe='/tmp/tool'))
        alert = self.rules(self.event(2, exe='/usr/bin/sh', euid='0'))['behavior-root-transition']
        self.assertEqual(alert.severity, 'high')
        self.assertIn('PID reuse', alert.detail)
        for changes in ({'ses': '8'}, {'pid': '124'}, {'auid': '1001'}, {'ses': None}, {'euid': '1000'}):
            self.detector.reset_correlation()
            self.process(self.event(exe='/tmp/tool'))
            self.assertNotIn('behavior-root-transition', self.rules(self.event(2, **changes)))
        self.detector.reset_correlation()
        self.process(self.event(success='no'))
        self.assertNotIn('behavior-root-transition', self.rules(self.event(2, euid='0')))

    def test_port_sweep_counts_unique_ports_and_keeps_first_evidence(self):
        first = None
        for i in range(19):
            event = self.connect(i, port=1000+i, success='no', exit='-111')
            first = first or event.identity
            self.assertNotIn('network-port-sweep', self.rules(event))
        final = self.connect(20, port=1020, success='no', exit='-111')
        alert = self.rules(final)['network-port-sweep']
        self.assertEqual(alert.first_event, first)
        self.assertEqual(alert.severity, 'high')
        self.assertEqual(len(self.process(final)), 0)
        self.detector.reset_correlation()
        for i in range(25):
            self.assertNotIn('network-port-sweep', self.rules(self.connect(30+i, port=443)))

    def test_host_sweep_requires_failed_majority_or_scanner_name(self):
        for i in range(30):
            alerts = self.rules(self.connect(i, ip=f'192.0.2.{i+1}', success='no', exit='-111'))
        self.assertIn('network-host-sweep', alerts)
        self.detector.reset_correlation()
        for i in range(30):
            alerts = self.rules(self.connect(i, ip=f'192.0.2.{i+1}'))
        self.assertNotIn('network-host-sweep', alerts)
        self.detector.reset_correlation()
        for i in range(30):
            alerts = self.rules(self.connect(i, ip=f'192.0.2.{i+1}', exe='/usr/bin/nmap'))
        self.assertIn('network-host-sweep', alerts)

    def test_network_windows_do_not_mix_sessions_history_hosts_or_exec_images(self):
        for mode in ('session', 'history', 'host', 'exec', 'daemon', 'expired', 'missing'):
            self.detector.reset_correlation()
            for i in range(19):
                event = self.connect(i, port=1000+i)
                if mode == 'host':
                    event.records[0].node = 'other'
                self.process(event, historical=mode == 'history')
            if mode == 'exec': self.process(self.event(19))
            if mode == 'daemon': self.process(self.event(19, 'DAEMON_START'))
            changes = {'ses': '8'} if mode == 'session' else {'ses': None} if mode == 'missing' else {}
            self.assertNotIn('network-port-sweep', self.rules(self.connect(100 if mode == 'expired' else 20, port=2000, **changes)), mode)

    def test_periodic_signal_is_medium_and_rejects_private_or_irregular_series(self):
        for i in range(12): alerts = self.rules(self.connect(i*15))
        self.assertEqual(alerts['network-periodic'].severity, 'medium')
        self.assertIn('Legitimate polling', alerts['network-periodic'].detail)
        self.detector.reset_correlation()
        for i in range(12): alerts = self.rules(self.connect(i*15, ip='192.168.1.1'))
        self.assertNotIn('network-periodic', alerts)
        self.detector.reset_correlation()
        for i in range(12): alerts = self.rules(self.connect(i*i*3))
        self.assertNotIn('network-periodic', alerts)

    def test_persistence_to_network_does_not_treat_refusal_as_success(self):
        def origin():
            event = self.event(syscall='257', key='systemd_persistence')
            event.records.append(parse_line(f'type=PATH msg=audit({event.timestamp:.3f}:{self.serial}): name="/etc/systemd/system/example.service" nametype=NORMAL'))
            self.process(event)
            return event
        first = origin()
        self.assertNotIn('behavior-persistence-network', self.rules(self.connect(2, success='no', exit='-111')))
        alert = self.rules(self.connect(3, success='no', exit='-115'))['behavior-persistence-network']
        self.assertEqual(alert.first_event, first.identity)
        self.detector.reset_correlation(); origin(); self.process(self.event(1))
        self.assertNotIn('behavior-persistence-network', self.rules(self.connect(2)))

    def test_remote_tool_and_login_do_not_claim_unwanted_access(self):
        self.assertEqual(self.rules(self.event(exe='/usr/bin/wayvnc'))['remote-access-tool'].severity, 'medium')
        self.assertEqual(self.rules(self.event(exe='/tmp/sshd'))['remote-access-tool'].severity, 'high')
        login = self.event(1, 'USER_LOGIN', exe='/usr/bin/sshd', res='success', acct='root', addr='192.168.1.2')
        self.assertEqual(self.rules(login)['remote-login'].severity, 'high')
        for address in ('?', 'localhost', '127.0.0.1', '0.0.0.0'):
            self.assertNotIn('remote-login', self.rules(self.event(2, 'USER_START', exe='/usr/bin/sshd', res='success', addr=address)))
        self.assertNotIn('enumeration-tool', self.rules(self.event(exe='/usr/bin/nmap', success='no')))

    def test_buckets_are_bounded_and_historical_findings_do_not_notify(self):
        for i in range(300): self.process(self.connect(i, pid=str(1000+i)))
        self.assertLessEqual(len(self.detector.chokepoints.attempts), 256)
        self.assertLessEqual(len(self.detector.chokepoints.series), 256)
        result = self.process(self.event(301, exe='/usr/bin/nmap'), historical=True)
        self.assertFalse(any(alert.notify for alert in result))

    def test_nearby_context_is_host_only_and_explicitly_not_causal(self):
        anchor = self.event(exe='/usr/bin/nmap')
        self.process(anchor)
        nearby = self.event(1, exe='/usr/bin/sbctl', pid='200')
        self.process(nearby)
        other = self.event(2); other.records[0].node = 'other'; self.process(other)
        self.process(self.event(70))
        alert_id = next(row[0] for row in self.store.rows(alerts=True) if row[2] == 'enumeration-tool')
        rows, limit = self.store.nearby_context(alert_id)
        self.assertEqual([row[0] for row in rows], [nearby.identity])
        self.assertIn('may be unrelated', limit)
        self.assertEqual(self.store.nearby_context(-1)[0], [])

    def test_saved_paths_operations_and_unset_names_are_plain_and_bounded(self):
        event = self.event(syscall='257', exe='/usr/bin/sbctl')
        event.records.append(parse_line(f'type=CWD msg=audit({event.timestamp:.3f}:{self.serial}): cwd="/boot/EFI/limine"'))
        event.records.append(parse_line(f'type=PATH msg=audit({event.timestamp:.3f}:{self.serial}): name="limine_x64.efi" nametype=NORMAL'))
        data = event.summary()
        self.assertEqual(data['targets'], [{'path': '/boot/EFI/limine/limine_x64.efi', 'kind': 'NORMAL'}])
        self.assertIn('openat', data['operation'])
        self.assertNotIn('cwd', data)
        self.assertIn('unset', user_label('4294967295', {}))
        self.assertIn('current local', user_label('1000', {'1000': 'demo'}))
        from skidplate.ui import Dashboard
        text = Dashboard.saved_details(SimpleNamespace(local_accounts={'1000': 'demo'}), dict(data, auid='4294967295'))
        self.assertIn('POSSIBLE MAINTENANCE', text)
        self.assertIn('unset', text)
        self.assertIn('not a current socket', Dashboard.saved_details(SimpleNamespace(local_accounts={}), dict(data, connections=[{'ip':'8.8.8.8', 'port':443}])))

    def test_local_account_reader_rejects_symlinks_and_oversized_files(self):
        path = Path(self.temp.name) / 'passwd'
        path.write_text('demo:x:1000:1000:Name:/home/demo:/bin/bash\n')
        self.assertEqual(local_accounts(path), {'1000': 'demo'})
        link = Path(self.temp.name) / 'link'; link.symlink_to(path)
        self.assertEqual(local_accounts(link), {})
        path.write_bytes(b'x' * (256*1024 + 1))
        self.assertEqual(local_accounts(path), {})


if __name__ == '__main__':
    unittest.main()
