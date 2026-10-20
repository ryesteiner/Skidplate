"""Transient argument semantics, privacy and draft collection, all synthetic."""
import json
from pathlib import Path
import tempfile
import unittest

from skidplate.core import Detector, Store, parse_line
from skidplate.sigma_engine import SigmaEngine
from test_sigma_noise import event
from tools.build_sigma_profile import build


class ArgumentTests(unittest.TestCase):
    def setUp(self):
        self.engine = SigmaEngine()

    def ids(self, body, kind='EXECVE', extra=None):
        return {m['id'] for m in self.engine.detect(event(rows=[(kind, body)] + (extra or [])))}

    def test_all_bundled_rules_compile_and_argument_patterns_match(self):
        self.assertEqual(sum(r.metadata['source_kind'] == 'auditd' for r in self.engine.rules), 30)
        cases = [
            ('cb39d16b', 'argc=2 a0="wget" a1="--post-file=/tmp/file"'),
            ('a5b977d6', 'argc=3 a0="chattr" a1="-i" a2="/tmp/file"'),
            ('071d5e5a', 'argc=2 a0="miner" a1="--cpu-priority=5"'),
            ('323ff3f5', 'argc=3 a0="nft" a1="flush" a2="ruleset"'),
            ('1543ae20', 'argc=3 a0="chmod" a1="777" a2="/tmp/file"'),
            ('9d4548fa', 'argc=3 a0="cp" a1="/bin/sh" a2="/tmp/crond"'),
            ('70b4156e', 'argc=5 a0="iptables" a1="-t" a2="nat" a3="--to-ports" a4="42392"'),
            ('c52a914f', 'argc=4 a0="truncate" a1="-s" a2="500" a3="/tmp/file"'),
            ('df3fcaea', 'argc=3 a0="grep" a1="password" a2="/tmp/file"'),
            ('b3cec4e7', 'argc=4 a0="touch" a1="-t" a2="202601010000" a3="/tmp/file"'),
            ('eae8ce9f', 'argc=2 a0="cat" a1=".bash_history"'),
            ('e497a24e', 'argc=3 a0="sysctl" a1="-w" a2="kernel.randomize_va_space=0"'),
        ]
        for prefix, body in cases:
            with self.subTest(prefix=prefix):
                self.assertTrue(any(identity.startswith(prefix) for identity in self.ids(body)))

    def test_numeric_syscall_a0_is_not_command_argv_or_a_pointer(self):
        for arch, personality, syslog in [('c000003e', 135, 103), ('40000003', 136, 103), ('c00000b7', 92, 116)]:
            self.assertTrue(any(i.startswith('e497a24e') for i in self.ids(
                f'arch={arch} syscall={personality} a0=00040000', 'SYSCALL')))
            self.assertTrue(any(i.startswith('eca5e022') for i in self.ids(
                f'arch={arch} syscall={syslog} a0=0005', 'SYSCALL')))
        for body in ['arch=unknown syscall=135 a0=40000', 'arch=c000003e syscall=59 a0=40000',
                     'arch=c000003e syscall=135 a0=invalid', 'arch=c000003e syscall=103 a0=3']:
            self.assertFalse(self.ids(body, 'SYSCALL'))
        self.assertFalse(any(i.startswith('e497a24e') for i in self.ids('argc=1 a0="40000"')))

    def test_hex_argv_and_complete_keyword_negation(self):
        hex_value = '--post-file=/tmp/private file'.encode().hex()
        self.assertTrue(any(i.startswith('cb39d16b') for i in self.ids(f'argc=2 a0="wget" a1={hex_value}')))
        # The upstream dd rule excludes an of= keyword; never evaluate its NOT
        # against a truncated vector or separate/fragmented EXECVE records.
        self.assertTrue(any(i.startswith('c52a914f') for i in self.ids('argc=2 a0="dd" a1="if=/tmp/input"')))
        self.assertFalse(any(i.startswith('c52a914f') for i in self.ids('argc=3 a0="dd" a1="if=/tmp/input" a2="of=/tmp/output"')))
        self.assertFalse(self.ids('argc=3 a0="dd" a1="if=/tmp/input"'))
        self.assertFalse(self.ids('argc=2 a0="dd" a1="if=/tmp/input"', extra=[('EXECVE', 'argc=3 a2="of=/tmp/output"')]))

    def test_incomplete_invalid_and_oversized_arguments_reject_whole_view(self):
        cases = ['a0="wget" a1="--post-file=/tmp/file"',
                 'argc=17 a0="wget" a1="--post-file=/tmp/file"',
                 'argc=2 a0="wget" a0="curl" a1="--post-file=/tmp/file"',
                 'argc=2 a0="wget" a1_len=1000 a1[0]=6162',
                 'argc=2 a0="wget" a1=ff', 'argc=2 a0="wget" a1=0a',
                 'argc=2 a0="wget" a1="' + 'x' * 513 + '"',
                 'argc=9 ' + ' '.join(f'a{i}="' + 'x' * 512 + '"' for i in range(9))]
        for body in cases:
            with self.subTest(body=body[:60]):
                row = event(rows=[('EXECVE', body)]).records[0]
                self.assertEqual(row.sigma_arguments, {})
                self.assertFalse(self.engine.detect(event(rows=[('EXECVE', body)])))

    def test_no_plaintext_arguments_saved_or_used_for_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / 'state')
            try:
                detector = Detector(store)
                detector.argument_context = False  # Strict no-argv persistence remains selectable.
                def attempt(serial, secret):
                    return event(serial, [('SYSCALL', 'arch=c000003e syscall=59 success=yes exe="/usr/bin/wget"'),
                                          ('EXECVE', f'argc=2 a0="wget" a1="--post-file={secret}"')])
                secret = 'UNIQUE_PRIVATE_$(touch do-not-execute)'
                source = attempt(1, secret)
                self.assertNotIn(secret, repr(source.records[-1]))
                alerts = detector.process(source)
                match = next(a for a in alerts if a.rule.startswith('sigma:cb39d16b'))
                self.assertNotIn(secret, match.detail)
                self.assertNotIn(secret, json.dumps(source.summary()))
                self.assertNotIn(secret, str(list(store.db.iterdump())))
                self.assertNotIn('a0', source.records[-1].values)
                row = next(r for r in store.rows(alerts=True) if r[2] == match.rule)
                detector.ignores.save(match.rule, {'fingerprint': row[7]}, 'one exact context', 600)
                self.assertFalse(any(a.rule == match.rule for a in detector.process(attempt(2, secret))))
                self.assertTrue(any(a.rule == match.rule for a in detector.process(attempt(3, 'DIFFERENT_PRIVATE'))))
            finally:
                store.db.close()

    def test_collection_draft_is_targeted_additive_and_broad_mode_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'usr/bin').mkdir(parents=True)
            (root / 'usr/bin/wget').touch(); (root / 'usr/bin/chmod').touch()
            (root / 'usr/bin/curl').symlink_to(root / 'usr/bin/wget')
            rules, skipped = build(root)
            self.assertIn('/usr/bin/curl', skipped)
            self.assertTrue(any('path=/usr/bin/wget' in r and 'susp_activity' in r for r in rules))
            self.assertTrue(any('-S personality -F a0&=0x40000' in r for r in rules))
            self.assertFalse(any('sentinel_sigma_all_exec' in r for r in rules))
            broad, _ = build(root, all_exec=True)
            self.assertEqual(sum('sentinel_sigma_all_exec' in r for r in broad), 2)
            self.assertTrue(all(r.startswith(('-A always,exit ', '-a always,exit ')) for r in broad))


if __name__ == '__main__':
    unittest.main()
