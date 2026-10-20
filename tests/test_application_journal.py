"""No live journals: validate origins, data-only matching and cursor retries."""
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from skidplate.application_journal import ApplicationJournal, Source, journal_command, parse_entry, parse_sources
from skidplate.core import Detector, Event, Store, parse_line
from skidplate.sigma_engine import SigmaEngine


def line(source, message, cursor='s=abc;i=1', **changes):
    data = {'MESSAGE': message, 'PRIORITY': '6', '_UID': str(os.getuid()), '_PID': '123',
            '_EXE': '/usr/bin/runtime', '_MACHINE_ID': 'a' * 32, '_BOOT_ID': 'b' * 32,
            '__REALTIME_TIMESTAMP': str(int(time.time() * 1_000_000)), '__CURSOR': cursor,
            '_SYSTEMD_USER_UNIT' if source.scope == 'user' else '_SYSTEMD_UNIT': source.unit}
    data.update(changes)
    return json.dumps(data)


class ApplicationTests(unittest.TestCase):
    def test_exact_sources_and_no_option_glob_or_duplicate_injection(self):
        sources = parse_sources('user:python:app.service; system:nodejs:web@one.service')
        self.assertEqual(len(sources), 2)
        for text in ['system:python:*.service', 'system:python:--all.service',
                     'user:ruby:app.service', 'system:nodejs:../../app.service',
                     'system:nodejs:app.service\n--all',
                     'user:python:app.service; user:nodejs:app.service']:
            with self.subTest(text=text), self.assertRaises(ValueError): parse_sources(text)
        command = journal_command(sources[0], '', 100)
        self.assertEqual(command[0], '/usr/bin/journalctl')
        self.assertIn('--user', command)
        self.assertIn('_UID=' + str(os.getuid()), command)
        self.assertIn('_SYSTEMD_USER_UNIT=app.service', command)
        self.assertFalse(any('_CMDLINE' in part for part in command))
        self.assertFalse(any('--priority' in part for part in command))
        with self.assertRaises(ValueError): journal_command(sources[0], 'cursor\n--all', 100)

    def test_rules_are_scoped_to_selected_product_and_never_audit_arguments(self):
        engine = SigmaEngine()
        self.assertEqual(sum(r.metadata['source_kind'] == 'application' for r in engine.rules), 3)
        for product, text, prefix in [('python', 'ProgrammingError: database failed', '19aefed0'),
                                      ('ruby_on_rails', 'ActionController::BadRequest', '0d2c3d4c'),
                                      ('nodejs', 'Error at node:child_process:1', '97661d9d')]:
            source = Source('user', product, 'app.service')
            record, _ = parse_entry(line(source, text), source)
            matches = engine.detect(Event([record]))
            self.assertEqual(len(matches), 1)
            self.assertTrue(matches[0]['id'].startswith(prefix))
            wrong = Source('system', 'nodejs' if product != 'nodejs' else 'python', 'app.service')
            self.assertFalse(engine.detect(Event([parse_entry(line(wrong, text), wrong)[0]])))
        audit = parse_line('type=EXECVE msg=audit(1700000000.123:1): argc=2 a0="python" a1="ProgrammingError"')
        self.assertFalse(engine.detect(Event([audit])))

    def test_trusted_journal_origin_and_bounds_are_rechecked(self):
        source = Source('user', 'python', 'app.service')
        for changes in [{'_SYSTEMD_USER_UNIT': 'other.service'}, {'_UID': str(os.getuid() + 1)},
                        {'PRIORITY': '9'}, {'MESSAGE': ['binary']}, {'MESSAGE': 'x' * 16385},
                        {'_PID': '--all'}, {'_BOOT_ID': 'not-a-boot'}, {'__CURSOR': 'bad cursor'}]:
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                parse_entry(line(source, 'DataError', **changes), source)
        raw = line(source, 'DataError')
        with self.assertRaises(ValueError):parse_entry(raw[:-1] + ',"MESSAGE":"duplicate"}', source)

    def test_error_text_not_saved_and_unmatched_entries_not_persisted(self):
        source = Source('system', 'python', 'app.service')
        message = 'DataError SQL password=UNIQUE_PRIVATE_TOKEN'
        record, _ = parse_entry(line(source, message), source)
        self.assertNotIn(message, repr(record))
        with tempfile.TemporaryDirectory() as temporary:
            store = Store(Path(temporary) / 'state')
            try:
                detector = Detector(store)
                alerts = detector.process(Event([record]))
                self.assertEqual(len(alerts), 1)
                self.assertIn('DataError', alerts[0].detail)
                self.assertIn('app.service', alerts[0].detail)
                self.assertNotIn('UNIQUE_PRIVATE_TOKEN', alerts[0].detail)
                self.assertNotIn('UNIQUE_PRIVATE_TOKEN', str(list(store.db.iterdump())))
                detector.process(Event([parse_entry(line(source, 'ordinary message', 's=abc;i=2'), source)[0]]))
                self.assertEqual(len(store.rows()), 1)
            finally:store.db.close()

    def test_single_pending_batch_cursor_advances_only_after_acknowledgement(self):
        source = Source('user', 'python', 'app.service')
        follower = ApplicationJournal((source,), now=100)
        with patch('skidplate.application_journal.bounded_query', return_value=line(source, 'DataError')):
            follower._query(source)
        follower.worker = SimpleNamespace(is_alive=lambda: False)
        rows = follower.poll(now=1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(follower.cursors, {})
        self.assertEqual(follower.poll(now=2), [])
        with self.assertRaises(ValueError):follower.configure(())
        follower.retry_pending()
        self.assertEqual(follower.cursors, {})
        with patch('skidplate.application_journal.bounded_query', return_value=line(source, 'DataError')):
            follower._query(source)
        follower.worker = SimpleNamespace(is_alive=lambda: False)
        follower.poll(now=3)
        follower.acknowledge()
        self.assertEqual(follower.cursors[source.key], 's=abc;i=1')
        follower.configure(())
        self.assertEqual(follower.poll(now=10), [])
        follower.close()


if __name__ == '__main__':unittest.main()
