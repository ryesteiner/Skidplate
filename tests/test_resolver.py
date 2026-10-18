import json
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from skidplate.core import Detector, Event, Store, parse_line
from skidplate.resolver import (DNSSEC_EVENTS, RESOLVER_EXE, RESOLVER_UNIT,
    ResolverFollower, bounded_query, journal_command, parse_resolver_line)
from tools.build_audit_profile import build_dns


def journal_line(cursor="s=abc;i=1", message="DNSSEC validation failed for private.example", message_id=None):
    return json.dumps({"MESSAGE_ID": message_id or next(iter(DNSSEC_EVENTS)),
        "MESSAGE": message, "_SYSTEMD_UNIT": RESOLVER_UNIT, "_EXE": RESOLVER_EXE,
        "__REALTIME_TIMESTAMP": str(int(time.time() * 1_000_000)), "__CURSOR": cursor})


class ResolverTests(unittest.TestCase):
    def test_exact_catalog_events_and_origin_validation(self):
        for message_id, kind in DNSSEC_EVENTS.items():
            row, cursor = parse_resolver_line(journal_line(message_id=message_id))
            self.assertEqual(row.kind, kind)
            self.assertEqual(cursor, "s=abc;i=1")
        for key, value in (("_SYSTEMD_UNIT", "other.service"), ("_EXE", "/tmp/fake"),
                           ("MESSAGE_ID", "unknown"), ("__CURSOR", "bad\n--help"),
                           ("__REALTIME_TIMESTAMP", "NaN"), ("MESSAGE", ["ambiguous"])):
            data = json.loads(journal_line())
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                parse_resolver_line(json.dumps(data))
        for bad in ("[]", "{", "x" * 65537, '{"a":1,"a":2}', "[" * 2000):
            with self.assertRaises(ValueError):
                parse_resolver_line(bad)

    def test_dns_security_alert_privacy_snooze_scope_and_history(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            detector = Detector(store)
            now = time.time()
            first, _ = parse_resolver_line(journal_line())
            alert = detector.process(Event([first]), now=now)[0]
            self.assertEqual(alert.rule, "dnssec-validation")
            self.assertTrue(alert.wants_notification())
            store.snooze_alert(store.rows(alerts=True)[0][0], 600, now=now)
            other, _ = parse_resolver_line(journal_line("s=abc;i=2", "DNSSEC validation failed for another.example"))
            self.assertTrue(detector.process(Event([other]), now=now + 1)[0].notify)
            repeated, _ = parse_resolver_line(journal_line("s=abc;i=3"))
            self.assertFalse(detector.process(Event([repeated]), now=now + 61)[0].notify)
            historical, _ = parse_resolver_line(journal_line("s=abc;i=4", message_id=list(DNSSEC_EVENTS)[1]))
            self.assertFalse(detector.process(Event([historical]), now=now, historical=True)[0].notify)
            all_saved = str(store.rows()) + str(store.rows(alerts=True))
            self.assertNotIn("private.example", all_saved)
            self.assertNotIn("another.example", all_saved)
            store.db.close()

    def test_fixed_command_cursor_and_capture_limits(self):
        command = journal_command("s=abc;i=2", 100)
        self.assertEqual(command[0], "/usr/bin/journalctl")
        self.assertIn("--no-pager", command)
        self.assertIn("--lines=+200", command)
        self.assertIn("--after-cursor=s=abc;i=2", command)
        self.assertIn(f"_SYSTEMD_UNIT={RESOLVER_UNIT}", command)
        self.assertIn(f"_EXE={RESOLVER_EXE}", command)
        self.assertEqual(sum(arg.startswith("MESSAGE_ID=") for arg in command), 3)
        with self.assertRaises(ValueError):
            journal_command("bad cursor --directory=/tmp", 100)
        stopped = threading.Event()
        with patch("skidplate.resolver.MAX_OUTPUT", 4096), self.assertRaises(ValueError):
            bounded_query([sys.executable, "-c", "import sys; sys.stdout.write('x'*65536)"], stopped)
        with patch("skidplate.resolver.QUERY_TIMEOUT", 0.05), self.assertRaises(ValueError):
            bounded_query([sys.executable, "-c", "import time; time.sleep(2)"], stopped)
        with self.assertRaises(ValueError):
            bounded_query([sys.executable, "-c", "import sys; sys.stderr.write('unavailable')"], stopped)

    def test_background_poll_acknowledges_only_after_processing(self):
        reader = ResolverFollower(now=time.time())
        gate = threading.Event()
        def query(*_):
            gate.wait(timeout=1)
            return journal_line() + "\n"
        with patch("skidplate.resolver.bounded_query", side_effect=query):
            self.assertEqual(reader.poll(now=0), [])
            self.assertEqual(reader.poll(now=0.1), [])
            gate.set()
            reader.worker.join(timeout=1)
            self.assertFalse(reader.worker.is_alive())
            rows = reader.poll(now=1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(reader.cursor, "")
            self.assertEqual(reader.poll(now=2), [])
            reader.acknowledge()
            self.assertEqual(reader.cursor, "s=abc;i=1")
        reader.close()

    def test_unavailable_or_bad_batch_keeps_cursor(self):
        for response in ("garbage\n", journal_line() + "\n" + "bad\n"):
            reader = ResolverFollower()
            reader.cursor = "s=prior;i=9"
            with patch("skidplate.resolver.bounded_query", return_value=response):
                reader.poll(now=0)
                reader.worker.join(timeout=1)
                self.assertEqual(reader.poll(now=1), [])
                self.assertTrue(reader.status.startswith("DNSSEC telemetry unavailable"))
                self.assertEqual(reader.cursor, "s=prior;i=9")
            reader.close()

    def test_dns_path_signal_from_existing_broad_watch_and_no_false_change(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            detector = Detector(store)
            def event(serial, parent, result="yes"):
                prefix = f"msg=audit({time.time():.3f}:{serial}): "
                return Event([parse_line('type=SYSCALL ' + prefix + f'success={result} key=sentinel_config_change exe="/usr/bin/editor"'),
                    parse_line('type=PATH ' + prefix + f'name="{parent}" nametype=PARENT'),
                    parse_line('type=PATH ' + prefix + 'name="resolv.conf" nametype=CREATE')])
            alert = detector.process(event(100, "/etc"))[0]
            self.assertEqual(alert.rule, "dns-config-change")
            self.assertEqual(alert.severity, "high")
            self.assertEqual(detector.process(event(101, "/etc", "no")), [])
            other = detector.process(event(102, "/tmp"))[0]
            self.assertEqual(other.rule, "configuration-change")
            store.db.close()

    def test_dns_profile_precedes_broad_rules_and_avoids_transient_boot_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/systemd/resolved.conf.d").mkdir(parents=True)
            (root / "etc/hosts").touch()
            (root / "etc/resolv.conf").symlink_to("/run/systemd/resolve/stub-resolv.conf")
            rules, skipped = build_dns(root)
            self.assertEqual(len(rules), 4)
            self.assertTrue(all(line.startswith("-A always,exit -F arch=b") for line in rules))
            self.assertTrue(all("-k sentinel_dns_config" in line for line in rules))
            self.assertFalse(any("/run/" in line for line in rules))
            self.assertIn("/etc/resolv.conf", skipped)


if __name__ == "__main__":
    unittest.main()
