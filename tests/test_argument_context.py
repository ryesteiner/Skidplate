"""Persisted evidence must remain bounded data with explicit privacy limits."""
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from skidplate.argument_context import describe_arguments, escaped_data, MAX_CONTEXT
from skidplate.core import Detector, Event, Store, parse_line


def captured(arguments, serial=1, exe='/usr/bin/chmod', euid='1000'):
    ts = f'{time.time():.6f}'
    body = f'argc={len(arguments)} ' + ' '.join(f'a{i}={value.encode().hex()}' for i, value in enumerate(arguments))
    return Event([parse_line(f'type=SYSCALL msg=audit({ts}:{serial}): arch=c000003e syscall=59 success=yes euid={euid} exe="{exe}"'),
                  parse_line(f'type=EXECVE msg=audit({ts}:{serial}): {body}')])


class ContextTests(unittest.TestCase):
    def test_common_credentials_headers_bodies_and_urls_are_masked(self):
        arguments = ['curl', '--password', 'LEAK_PASSWORD', '--api-key=LEAK_KEY',
            'PGPASSWORD=LEAK_ENV', '-uLEAK_USER:LEAK_PASS', '-H', 'Authorization: Bearer LEAK_HEADER',
            '--url', 'https://user:LEAK_URL@example.invalid/private?token=LEAK_QUERY',
            '--data', 'LEAK_BODY', '--post-file=/tmp/evidence.txt', '-v']
        text = describe_arguments(captured(arguments))
        self.assertNotIn('LEAK_', text)
        self.assertIn('example.invalid', text)
        self.assertIn('/tmp/evidence.txt', text)
        self.assertIn('REDACTED', text)
        self.assertIn('Unknown secrets may remain', text)

    def test_shell_payload_is_escaped_data_and_no_command_interface_called(self):
        source = captured(['/tmp/helper', '$(touch marker); id | cat & echo < x > y `id`'])
        with patch('os.system', side_effect=AssertionError('execution forbidden')), \
             patch('subprocess.run', side_effect=AssertionError('execution forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')):
            text = describe_arguments(source)
        line = next(line for line in text.splitlines() if line.startswith('arg[1]'))
        self.assertNotIn('$(', line)
        self.assertNotIn('`', line)
        self.assertIn('\\u0024\\u0028', line)
        self.assertNotIn('\u202e', escaped_data('x\u202ey\nz'))
        self.assertNotIn('\n', escaped_data('x\u202ey\nz'))
        self.assertIn('Never paste evidence into a terminal', text)

    def test_url_assignments_do_not_preserve_userinfo_before_query_redaction(self):
        for value in ['https://name:LEAK_URL@example.invalid/path?token=LEAK_QUERY',
                      'https://name:LEAK_URL=more@example.invalid/path?q=LEAK_QUERY',
                      '--url=https://name:LEAK_URL@example.invalid/path?token=LEAK_QUERY']:
            with self.subTest(value=value):
                text = describe_arguments(captured(['curl', value]))
                self.assertNotIn('LEAK_', text)
                self.assertIn('example.invalid', text)

    def test_compact_flags_are_redacted_before_option_and_assignment_parsing(self):
        values = ['-pLEAK_PASSWORD', '-uLEAK_PASSWORD=extra', '-HAuthorization: Bearer LEAK_TOKEN==',
                  '-cLEAK_CODE=secret', '-eLEAK_CODE', '-dLEAK_BODY=value', '-Fpassword=LEAK_FORM']
        text = describe_arguments(captured(['tool'] + values))
        self.assertNotIn('LEAK_', text)
        self.assertEqual(text.count('[REDACTED VALUE]'), len(values))

    def test_inline_code_payloads_and_structured_values_are_hidden(self):
        text = describe_arguments(captured(['python', '-c', 'LEAK_CODE_PASSWORD', '{"password":"LEAK_JSON"}']))
        self.assertNotIn('LEAK_', text)
        self.assertIn('arg[1]: "-c"', text)

    def test_context_budget_and_incomplete_argv(self):
        text = describe_arguments(captured(['tool'] + ['é' * 128] * 15))
        self.assertLessEqual(len(text), MAX_CONTEXT)
        self.assertIn('omitted', text)
        incomplete = captured(['tool'])
        incomplete.records[-1].sigma_arguments.clear()
        self.assertEqual(describe_arguments(incomplete), '')

    def test_alert_context_saved_while_summary_and_disabled_mode_exclude_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / 'state')
            try:
                detector = Detector(store)
                source = captured(['chmod', '777', '/tmp/investigate'])
                alerts = detector.process(source)
                match = next(a for a in alerts if a.rule.startswith('sigma:1543ae20'))
                self.assertIn('arg[1]: "777"', match.detail)
                self.assertIn('cmd1.a1', match.detail)
                self.assertNotIn('/tmp/investigate', str(source.summary()))
                store.set('argument_context', '0')
                disabled = Detector(store)
                later = disabled.process(captured(['chmod', '777', '/tmp/other'], 2))
                self.assertTrue(later)
                self.assertTrue(all('SAVED COMMAND ARGUMENTS' not in a.detail for a in later))
                self.assertIn('SAVED COMMAND ARGUMENTS', str(store.rows(alerts=True)))
            finally:store.db.close()

    def test_local_alert_exact_exception_distinguishes_argument_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / 'state')
            try:
                detector = Detector(store)
                detector.process(captured(['/tmp/helper', 'one'], exe='/tmp/helper', euid='0'))
                row = next(r for r in store.rows(alerts=True) if r[2] == 'root-temp-exec')
                detector.ignores.save(row[2], {'fingerprint': row[7]}, 'only this command context', 600)
                alerts = detector.process(captured(['/tmp/helper', 'two'], 2, exe='/tmp/helper', euid='0'))
                self.assertTrue(any(a.rule == 'root-temp-exec' for a in alerts))
            finally:store.db.close()


if __name__ == '__main__':unittest.main()
