import json
import ipaddress
import os
from pathlib import Path
import subprocess
import sys
import sqlite3
import tempfile
import time
import unittest

from skidplate.core import (Alert, Assembler, Detector, Event, LogFollower,
    KEY_SIGNALS, MAX_ALERTS, MAX_EVENTS, MAX_LINE, Store, clean, fields, network_destinations,
    network_watchlist, parse_line)
from skidplate.demo import sample
from tools.build_audit_profile import build


def record(kind="SYSCALL", serial=1, timestamp=None, body=""):
    ts = time.time() if timestamp is None else timestamp
    return parse_line(f"type={kind} msg=audit({ts:.3f}:{serial}): {body}")


class ParserTests(unittest.TestCase):
    def test_field_scanner_compatibility(self):
        self.assertEqual(fields('bare_identifier 9uid=0 uid=1 (euid=1000) '
            'acct="two words" key=74657374 empty="" missing= res=failed'),
            {"uid": "0", "euid": "1000)", "acct": "two words",
             "key": "test", "empty": "", "res": "failed"})
        self.assertEqual(fields(r'acct="a\"b" res=failed'),
                         {"acct": r'a\"b', "res": "failed"})
        # Preserve the existing unquoted fallback for unfinished quotes.
        self.assertEqual(fields('acct="unfinished res=failed'),
                         {"acct": '"unfinished', "res": "failed"})
        self.assertEqual(fields("uid=0 msg='msg=res=success res=failed uid=evil'"),
                         {"uid": "0", "res": "failed"})

    def test_maximum_size_adversarial_fields_are_bounded(self):
        # Keep a regression from hanging the test runner. The old unanchored
        # regex exceeds this CPU limit on the first accepted-size bare field.
        script = r'''
import resource
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
from skidplate.core import MAX_LINE, parse_line
header = "type=USER_AUTH msg=audit(1700000000.123:1): "
cases = [
    (header + "a" * (MAX_LINE - len(header)), {}),
    ("a" * (MAX_LINE - len(header) - 1) + " " + header, {}),
    (header + "msg='" + "a" * (MAX_LINE - len(header) - 6) + "'", {}),
    (header + "a" * (MAX_LINE - len(header) - 6) + " uid=0", {"uid": "0"}),
    (header + "a" * (MAX_LINE - len(header) - 2) + "= ", {}),
    (header + 'acct="' + "a" * (MAX_LINE - len(header) - 7) + "\\",
     {"acct": ('"' + "a" * 256)[:256]}),
    (header + 'acct="' + "\\a" * ((MAX_LINE - len(header) - 6) // 2),
     {"acct": ('"' + "\\a" * 256)[:256]}),
]
for line, expected in cases:
    assert len(line) <= MAX_LINE
    row = parse_line(line)
    assert row is not None and row.values == expected
'''
        result = subprocess.run([sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[1], capture_output=True,
            text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_nested_auth_and_enrichment(self):
        row = record("USER_AUTH", body='uid=0 auid=1000 msg=\'op=PAM:authentication acct="person" addr=192.0.2.2 res=failed\'\x1duid=evil')
        self.assertEqual(row.values["uid"], "0")
        self.assertEqual(row.values["acct"], "person")
        self.assertEqual(row.values["res"], "failed")

    def test_nested_subject_override_rejected(self):
        row = record("USER_AUTH", body="uid=0 msg='uid=evil auid=0 res=failed'")
        self.assertEqual(row.values["uid"], "0")
        self.assertNotIn("auid", row.values)

    def test_syscall_success_is_authoritative_and_arguments_discarded(self):
        syscall = record(timestamp=100, body='success=no euid=0 exe="/tmp/program" a0="secret" proctitle=DEADBEEF')
        userspace = record("USER_AUTH", timestamp=100, body="msg='res=success'")
        event = Event([userspace, syscall])
        self.assertEqual(event.result, "no")
        self.assertNotIn("a0", syscall.values)
        self.assertNotIn("proctitle", syscall.values)

    def test_hex_encoded_path_and_account(self):
        exe = "/tmp/a program"
        row = record(body=f'exe={exe.encode().hex()} uid=1000')
        self.assertEqual(row.values["exe"], exe)
        self.assertEqual(row.values["uid"], "1000")

    def test_numeric_type_node_and_bad_input(self):
        row = parse_line('node=test type=1300 msg=audit(1700000000.123:22): uid=0')
        self.assertEqual(row.kind, "SYSCALL")
        self.assertTrue(row.identity.startswith("test:"))
        self.assertIsNone(parse_line('"; touch /tmp/this-is-only-data'))
        with self.assertRaises(ValueError):
            parse_line("x" * (MAX_LINE + 1))
        self.assertEqual(clean("<b>text</b>\x00\u202e"), "<b>text</b>")

    def test_assembler_interleaving_and_timeout(self):
        assembler = Assembler()
        a = record(serial=1, timestamp=100)
        b = record(serial=2, timestamp=100)
        self.assertEqual(assembler.feed(a, now=0), [])
        assembler.feed(b, now=0)
        self.assertEqual(len(assembler.feed(record("EOE", 1, 100), now=1)), 1)
        self.assertEqual(len(assembler.flush(now=2)), 1)


class FollowerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "audit.log"
        self.path.write_text("one\npartial")
        self.reader = LogFollower(self.path)

    def tearDown(self):
        self.reader.close()
        self.temp.cleanup()

    def test_append_and_partial(self):
        self.assertEqual(self.reader.poll(), ["one"])
        with self.path.open("a") as handle:
            handle.write(" line\ntwo\n")
        self.assertEqual(self.reader.poll(), ["partial line", "two"])

    def test_rename_rotation_and_copytruncate(self):
        self.reader.poll()
        self.path.rename(self.path.with_suffix(".1"))
        self.path.write_text("fresh\n")
        self.assertEqual(self.reader.poll(), ["fresh"])
        self.path.write_text("x\n")
        self.assertEqual(self.reader.poll(), ["x"])
        self.assertEqual(self.reader.rotations, 2)

    def test_oversized_and_bounded_reads(self):
        self.path.write_bytes(b"x" * (MAX_LINE + 2) + b"\nvalid\n")
        rows = []
        for _ in range(20):
            rows.extend(self.reader.poll(budget=8192))
        self.assertEqual(rows, ["valid"])
        self.assertGreater(self.reader.skipped, 0)

    def test_symlink_and_fifo_refused(self):
        self.path.unlink()
        self.path.symlink_to("/etc/passwd")
        self.assertEqual(self.reader.poll(), [])
        self.assertIn("UNAVAILABLE", self.reader.status)
        self.path.unlink()
        os.mkfifo(self.path)
        self.assertEqual(self.reader.poll(), [])
        self.assertIn("regular file", self.reader.status)

    def test_tail_limit(self):
        self.path.write_text("older\nnewer\nlatest\n")
        reader = LogFollower(self.path, tail_bytes=12)
        self.assertEqual(reader.poll(), ["latest"])
        self.assertTrue(reader.recent_history)
        reader.close()

    def test_permission_loss_recovers_without_replaying_same_inode(self):
        from unittest.mock import patch
        self.path.write_text("before\n")
        self.assertEqual(self.reader.poll(), ["before"])
        with patch.object(Path, "stat", side_effect=PermissionError("denied")):
            self.assertEqual(self.reader.poll(), [])
        self.assertTrue(self.reader.access_lost)
        self.assertIn("Log access lost", self.reader.status)
        with self.path.open("a") as handle:
            handle.write("after\n")
        self.assertEqual(self.reader.poll(), ["after"])
        self.assertFalse(self.reader.access_lost)

    def test_rotated_unreadable_file_is_retried_from_start(self):
        from unittest.mock import patch
        self.path.write_text("before\n")
        self.reader.poll()
        self.path.rename(self.path.with_suffix(".1"))
        self.path.write_text("new\n")
        with patch("skidplate.core.os.open", side_effect=PermissionError("denied")):
            self.assertEqual(self.reader.poll(), [])
        self.assertTrue(self.reader.access_lost)
        self.assertEqual(self.reader.poll(), ["new"])
        self.assertFalse(self.reader.access_lost)

    def test_truncation_during_access_gap_resumes_from_start(self):
        from unittest.mock import patch
        self.path.write_text("long previous record\n")
        self.reader.poll()
        with patch.object(Path, "stat", side_effect=PermissionError("denied")):
            self.reader.poll()
        self.path.write_text("new\n")
        self.assertEqual(self.reader.poll(), ["new"])


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name))
        self.detector = Detector(self.store)
        self.now = time.time()

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def event(self, serial, kind="SYSCALL", body="", timestamp=None):
        return Event([record(kind, serial, self.now if timestamp is None else timestamp, body)])

    def test_selected_event_snooze_scope_persistence_expiry_and_history(self):
        def policy(serial, name="/example/one", profile="firefox", operation="open", pid=1, timestamp=None):
            return self.event(serial, "AVC", f'apparmor="DENIED" operation="{operation}" '
                f'profile="{profile}" name="{name}" pid={pid} exe="/usr/lib/firefox/firefox"', timestamp)
        self.assertTrue(self.detector.process(policy(100), now=self.now)[0].notify)
        alert_id = self.store.rows(alerts=True)[0][0]
        self.store.snooze_alert(alert_id, 3600, now=self.now)
        # A fresh engine reads persisted snoozes; changing PID is still a match.
        detector = Detector(self.store)
        self.assertFalse(detector.process(policy(101, pid=99), now=self.now + 61)[0].notify)
        self.assertEqual(len(self.store.rows(alerts=True)), 1)
        self.assertEqual(self.store.alert_stats()[alert_id][0], 2)
        self.assertTrue(detector.process(policy(102, name="/example/two"), now=self.now + 62)[0].notify)
        self.assertTrue(detector.process(policy(103, profile="other"), now=self.now + 63)[0].notify)
        self.assertTrue(detector.process(policy(104, operation="connect"), now=self.now + 64)[0].notify)
        self.assertTrue(detector.process(policy(105, timestamp=self.now + 3601), now=self.now + 3601)[0].notify)
        # Policy snooze must not silence unrelated high alerts.
        self.assertTrue(detector.process(self.event(106, "DAEMON_END"), now=self.now + 65)[0].notify)
        self.assertFalse(detector.process(policy(107), now=self.now + 7200, historical=True)[0].notify)

    def test_snooze_uses_full_target_before_truncation_and_can_be_cleared(self):
        body = 'apparmor="DENIED" profile="firefox" operation="open" name="'
        first = self.event(100, "AVC", body + "x" * 300 + 'one"')
        second = self.event(101, "AVC", body + "x" * 300 + 'two"')
        self.detector.process(first, now=self.now)
        self.store.snooze_alert(self.store.rows(alerts=True)[0][0], 600, now=self.now)
        self.assertTrue(self.detector.process(second, now=self.now + 1)[0].notify)
        self.store.clear_snoozes()
        repeated = self.event(102, "AVC", body + "x" * 300 + 'one"')
        self.assertTrue(self.detector.process(repeated, now=self.now + 61)[0].notify)

    def test_snooze_rejects_legacy_alert_and_invalid_duration(self):
        self.store.alert("policy-denial", "medium", "old", "old", self.now)
        alert_id = self.store.rows(alerts=True)[0][0]
        with self.assertRaises(ValueError):
            self.store.snooze_alert(alert_id, 3600, now=self.now)
        with self.assertRaises(ValueError):
            self.store.snooze_alert(alert_id, -1, now=self.now)

    def test_high_only_popups_preserve_medium_history_and_snooze_high_alerts(self):
        medium = self.detector.process(self.event(100, "AVC", 'apparmor="DENIED" profile="firefox" operation="open" name="/example/file"'), now=self.now)[0]
        self.assertFalse(medium.wants_notification())
        self.assertTrue(medium.wants_notification(high_only=False))
        self.assertEqual(len(self.store.rows(alerts=True)), 1)
        self.assertIn("operation=open", medium.detail)
        self.assertIn("target=/example/file", medium.detail)
        high = self.detector.process(self.event(101, "DAEMON_END"), now=self.now + 1)[0]
        self.assertTrue(high.wants_notification())
        self.store.snooze_alert(self.store.rows(alerts=True)[0][0], 600, now=self.now)
        repeated = Detector(self.store).process(self.event(102, "DAEMON_END"), now=self.now + 61)[0]
        self.assertFalse(repeated.wants_notification())
        self.assertFalse(repeated.wants_notification(high_only=False))

    def connection(self, serial, address="203.0.113.9", exe="/usr/bin/tool", success="yes", syscall="42"):
        ip = ipaddress.ip_address(address)
        raw = (b"\x02\x00\x01\xbb" + ip.packed + b"\x00" * 8 if ip.version == 4 else
               b"\x0a\x00\x01\xbb" + b"\x00" * 4 + ip.packed + b"\x00" * 4)
        return Event([record("SYSCALL", serial, self.now,
            f'arch=c000003e syscall={syscall} success={success} exe="{exe}"'),
            record("SOCKADDR", serial, self.now, f"saddr={raw.hex()}")])

    def test_network_explicit_watchlist_and_supported_connection_only(self):
        self.detector.watched_networks = network_watchlist("203.0.113.0/24, 2001:db8::/32")
        for serial, address in enumerate(("203.0.113.9", "2001:db8::9"), 100):
            event = self.connection(serial, address)
            self.assertEqual(network_destinations(event)[0][1], 443)
            alert = self.detector.process(event, now=self.now)[0]
            self.assertEqual(alert.rule, "network-watchlist")
            self.assertEqual(alert.severity, "high")
        self.assertEqual(self.detector.process(self.connection(103, "192.0.2.1"), now=self.now), [])
        self.assertEqual(self.detector.process(self.connection(104, success="no"), now=self.now), [])
        self.assertEqual(self.detector.process(self.connection(105, syscall="49"), now=self.now), [])
        self.assertEqual(self.detector.process(self.connection(108, "::ffff:203.0.113.9"), now=self.now)[0].rule, "network-watchlist")
        self.detector.watched_networks = ()
        self.assertEqual(self.detector.process(self.connection(106), now=self.now), [])
        temporary = self.detector.process(self.connection(107, exe="/tmp/tool"), now=self.now)[0]
        self.assertEqual(temporary.rule, "network-temp-exec")

    def test_network_invalid_unix_and_truncated_addresses_are_ignored(self):
        self.detector.watched_networks = network_watchlist("0.0.0.0/0 ::/0")
        for serial, raw in enumerate(("garbage", "020001bb", "0100" + "00" * 14,
                                     "0a0001bb" + "00" * 12), 100):
            event = self.connection(serial)
            event.records[-1] = record("SOCKADDR", serial, self.now, f"saddr={raw}")
            self.assertEqual(self.detector.process(event, now=self.now), [])
        for invalid in ("example.com", "192.0.2.999", "::/999", "1.1.1.1 " * 65, "x" * 8193):
            with self.assertRaises(ValueError):
                network_watchlist(invalid)

    def test_root_user_directory_execution_even_during_learning(self):
        for serial, path in enumerate(("/home/user/tool", "/run/user/1000/tool"), 100):
            alert = self.detector.process(self.event(serial, body=
                f'arch=c000003e syscall=59 success=yes euid=0 exe="{path}"'), now=self.now)[0]
            self.assertEqual(alert.rule, "root-user-exec")
            self.assertEqual(alert.severity, "high")

    def test_omarchy_and_reference_keys_are_detected_only_on_real_changes(self):
        for serial, (key, expected) in enumerate((
                ("identity_changes", "identity-change"), ("sudo_changes", "privilege-policy"),
                ("systemd_persistence", "persistence-change"), ("kernel_modules", "kernel-change"),
                ("sentinel_audit_config", "audit-tamper"), ("mac_policy", "security-policy-change"),
                ("sentinel_network_config", "network-policy-change"), ("sentinel_pacman_config", "package-config")), 100):
            event = self.event(serial, body=f'success=yes key="{key}" exe="/usr/bin/example"')
            self.assertEqual(self.detector.process(event, now=self.now)[0].rule, expected)
            failed = self.event(serial + 100, body=f'success=no exit=-13 key="{key}"')
            self.assertEqual(self.detector.process(failed, now=self.now), [])

    def test_file_change_snooze_distinguishes_full_path_and_preserves_evidence(self):
        def changed(serial, path):
            return Event([record("SYSCALL", serial, self.now, 'success=yes key=systemd_persistence exe="/usr/bin/editor"'),
                          record("PATH", serial, self.now, f'name="{path}"')])
        alert = self.detector.process(changed(100, "/etc/systemd/system/one.service"), now=self.now)[0]
        self.assertIn("target=/etc/systemd/system/one.service", alert.detail)
        self.store.snooze_alert(self.store.rows(alerts=True)[0][0], 600, now=self.now)
        second = self.detector.process(changed(101, "/etc/systemd/system/two.service"), now=self.now + 1)[0]
        self.assertTrue(second.notify)

    def test_numeric_operation_classes_do_not_retain_arguments_or_accept_injection(self):
        row = record(body='arch=c000003e syscall=101 a0=4 a1=1234 a2=secret ptrace_request=0 success=yes')
        self.assertEqual(row.values["ptrace_request"], "4")
        self.assertNotIn("a0", row.values)
        self.assertNotIn("a1", row.values)
        self.assertNotIn("a2", row.values)
        alert = self.detector.process(Event([row]), now=self.now)[0]
        self.assertEqual(alert.rule, "process-injection")
        for serial, body in enumerate((
            'arch=c000003e syscall=101 a0=0 ptrace_request=4 success=yes',
            'arch=c000003e syscall=1 ptrace_request=4 bpf_command=5 success=yes',
            'arch=unknown syscall=101 a0=4 success=yes',
            'arch=c000003e syscall=101 a0=4 success=no exit=-1'), 100):
            self.assertEqual(self.detector.process(self.event(serial, body=body), now=self.now), [])
        bpf = self.event(200, body='arch=c000003e syscall=321 a0=5 success=yes')
        self.assertEqual(self.detector.process(bpf, now=self.now)[0].rule, "bpf-program-load")

    def test_memory_execution_and_permission_denial_semantics(self):
        alert = self.detector.process(self.event(100, body='arch=c000003e syscall=59 success=yes euid=1000 exe="/memfd:loader (deleted)"'), now=self.now)[0]
        self.assertEqual(alert.rule, "memory-exec")
        denied = self.event(101, body='success=no exit=-13 key=sentinel_access_denied exe="/usr/bin/tool"')
        self.assertEqual(self.detector.process(denied, now=self.now)[0].rule, "access-denied")
        missing = self.event(102, body='success=no exit=-2 key=sentinel_access_denied')
        self.assertEqual(self.detector.process(missing, now=self.now), [])
        success = self.event(103, body='success=yes exit=3 key=sentinel_access_denied')
        self.assertEqual(self.detector.process(success, now=self.now), [])

    def test_nonblocking_network_attempt_is_not_claimed_as_completed(self):
        self.detector.watched_networks = network_watchlist("203.0.113.0/24")
        event = self.connection(100, exe="/tmp/tool", success="no")
        event.records[0] = record("SYSCALL", 100, self.now,
            'arch=c000003e syscall=42 success=no exit=-115 exe="/tmp/tool"')
        alerts = self.detector.process(event, now=self.now)
        self.assertEqual({alert.rule for alert in alerts}, {"network-watchlist", "network-temp-exec"})
        self.assertTrue(all("unknown" in alert.detail for alert in alerts))
        self.assertFalse(any("succeeded" in alert.detail for alert in alerts))

    def test_auth_correlation_dedup_and_cooldown(self):
        for i in range(4):
            self.assertEqual(self.detector.process(self.event(i, "USER_AUTH", "acct=user addr=192.0.2.1 res=failed"), now=self.now), [])
        event = self.event(5, "USER_AUTH", "acct=user addr=192.0.2.1 res=failed")
        self.assertEqual(self.detector.process(event, now=self.now)[0].rule, "auth-burst")
        self.assertEqual(self.detector.process(event, now=self.now), [])
        self.assertEqual(self.detector.process(self.event(6, "USER_AUTH", "acct=user addr=192.0.2.1 res=failed"), now=self.now + 1), [])

    def test_old_future_no_live_alert_or_learning(self):
        for i, timestamp in enumerate([self.now - 10000, self.now + 10000]):
            self.assertEqual(self.detector.process(self.event(i, "CONFIG_CHANGE", "enabled=0", timestamp), now=self.now), [])
        self.assertEqual(self.store.rows(alerts=True), [])
        self.assertEqual(self.detector.learning_until, 0)

    def test_history_detects_without_training_and_cannot_suppress_live(self):
        history = self.event(1, "CONFIG_CHANGE", "enabled=0", self.now - 1000)
        findings = self.detector.process(history, now=self.now, historical=True)
        self.assertIn("Historical finding", findings[0].detail)
        self.assertEqual(len(self.detector.process(self.event(2, "CONFIG_CHANGE", "enabled=0"), now=self.now)), 1)
        root = self.event(3, body='arch=c000003e syscall=59 success=yes euid=0 exe="/usr/bin/known"', timestamp=self.now - 1000)
        self.assertEqual(self.detector.process(root, now=self.now, historical=True), [])
        self.assertEqual(self.detector.learning_until, 0)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM baseline").fetchone()[0], 0)

    def test_history_auth_uses_event_time_not_replay_speed(self):
        for i in range(5):
            old = self.now - 10000 + i * 1000
            self.assertEqual(self.detector.process(self.event(i, "USER_AUTH", "acct=user res=failed", old), now=self.now, historical=True), [])

    def test_root_exec_learning_then_novelty(self):
        base = 'arch=c000003e syscall=59 success=yes euid=0 auid=1000 exe='
        self.assertEqual(self.detector.process(self.event(1, body=base+'"/usr/bin/known"'), now=self.now), [])
        self.assertGreater(self.detector.learning_until, self.now)
        self.detector.learning_until = self.now - 1
        self.assertEqual(self.detector.process(self.event(2, body=base+'"/usr/bin/known"'), now=self.now), [])
        self.assertEqual(self.detector.process(self.event(3, body=base+'"/usr/bin/new"'), now=self.now)[0].rule, "new-root-exec")
        encoded = "/tmp/a program".encode().hex()
        self.assertEqual(self.detector.process(self.event(4, body=base+encoded), now=self.now)[0].rule, "root-temp-exec")

    def test_nonexec_failed_or_user_no_root_alert(self):
        for i, suffix in enumerate(['syscall=2 success=yes euid=0', 'syscall=59 success=no euid=0', 'syscall=59 success=yes euid=1000']):
            body = 'arch=c000003e exe="/tmp/test" '+suffix
            self.assertEqual(self.detector.process(self.event(i, body=body), now=self.now), [])

    def test_audit_health_sensitive_and_mute(self):
        alerts = self.detector.process(self.event(1, "CONFIG_CHANGE", "enabled=0 res=1"), now=self.now)
        self.assertEqual(alerts[0].severity, "high")
        alerts = self.detector.process(self.event(2, "DAEMON_END"), now=self.now)
        self.assertEqual(alerts[0].rule, "audit-health")
        self.detector.muted.add("sensitive-change")
        self.assertEqual(self.detector.process(self.event(3, body='key="sentinel_identity" success=yes'), now=self.now), [])

    def test_failed_audit_disable_is_not_reported_as_disabled(self):
        alert = self.detector.process(self.event(1, "CONFIG_CHANGE", "enabled=0 res=0"), now=self.now)[0]
        self.assertEqual(alert.severity, "medium")
        self.assertNotEqual(alert.title, "Auditing disabled")

    def test_redacted_history_and_sql_metacharacters(self):
        body = '''exe="/usr/bin/tool" a0="secret-password" proctitle=DEADBEEF acct="';DROP TABLE events;--"'''
        self.detector.process(self.event(1, body=body), now=self.now)
        rows = self.store.rows()
        self.assertEqual(len(rows), 1)
        self.assertNotIn("secret-password", rows[0][2])
        self.assertNotIn("DEADBEEF", rows[0][2])

    def test_retention_limits(self):
        for i in range(MAX_EVENTS + 10):
            self.store.db.execute("INSERT INTO events VALUES(?,?,?)", (str(i), self.now, "{}"))
        for i in range(MAX_ALERTS + 10):
            self.store.alert("test", "medium", "test", "data", self.now)
        self.store.retain(now=self.now)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], MAX_EVENTS)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], MAX_ALERTS)

    def test_demo_produces_three_rules(self):
        assembler = Assembler()
        alerts = []
        for line in sample(self.now).splitlines():
            for event in assembler.feed(parse_line(line)):
                alerts.extend(self.detector.process(event, now=self.now))
        self.assertEqual({a.rule for a in alerts}, {"auth-burst", "audit-config", "root-temp-exec"})


class PrivateStateTests(unittest.TestCase):
    def test_existing_database_migration_preserves_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "skidplate.sqlite3"
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE alerts(id INTEGER PRIMARY KEY, ts REAL, rule TEXT, severity TEXT, title TEXT, detail TEXT, acknowledged INTEGER DEFAULT 0)")
            db.execute("INSERT INTO alerts VALUES(1,1,'old','medium','saved','evidence',0)")
            db.commit()
            db.close()
            path.chmod(0o600)
            store = Store(Path(directory))
            self.assertEqual(store.rows(alerts=True)[0][4], "saved")
            self.assertEqual(store.rows(alerts=True)[0][-1], "")
            self.assertEqual(store.active_snoozes(), {})
            store.db.close()


    def test_symlink_or_public_directory_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "state"
            target.mkdir(mode=0o755)
            with self.assertRaises(PermissionError): Store(target)
            link = base / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(PermissionError): Store(link)

    def test_database_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "skidplate.sqlite3").symlink_to(base / "elsewhere")
            with self.assertRaises(PermissionError): Store(base)


class CollectionProfileTests(unittest.TestCase):
    def test_additive_arch_profile_and_exact_rollback_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/pacman.d").mkdir(parents=True)
            (root / "usr/bin").mkdir(parents=True)
            (root / "usr/bin/pacman").touch()
            rules, skipped = build(root)
            self.assertIn("-a always,exit -F arch=b32 -S sys_kexec_load -k KEXEC", rules)
            self.assertIn("-a always,exit -F arch=b64 -S kexec_load -k KEXEC", rules)
            self.assertNotIn("-a always,exit -F arch=b32 -S kexec_load -k KEXEC", rules)
            self.assertTrue(any("dir=/etc/pacman.d" in line for line in rules))
            self.assertTrue(any("path=/usr/bin/pacman" in line for line in rules))
            self.assertIn("/etc/cron.d", skipped)
            self.assertTrue(all(line.startswith("-a always,exit -F arch=b") for line in rules))
            self.assertFalse(any("never," in line or "exclude" in line or "apt" in line for line in rules))
            self.assertFalse(any("/var/log/audit" in line for line in rules))
            known = set().union(*(keys for keys, _, _, _ in KEY_SIGNALS)) | {"sentinel_root_exec", "sentinel_connect"}
            self.assertTrue(all(line.rsplit(" -k ", 1)[1] in known for line in rules))
            for arch in ("b64", "b32"):
                specific = next(i for i, line in enumerate(rules) if f"arch={arch}" in line and "path=/usr/bin/pacman" in line)
                generic = next(i for i, line in enumerate(rules) if f"arch={arch}" in line and "-k sentinel_root_exec" in line)
                self.assertLess(specific, generic)


if __name__ == "__main__":
    unittest.main()
