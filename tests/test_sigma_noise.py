"""Actual default engine tests. Synthetic records only; no host log permissions."""
import json
from pathlib import Path
import tempfile
import time
import unittest

from skidplate.core import Detector, Event, Store, parse_line
from skidplate.sigma_engine import SigmaEngine, Unsupported, condition_tree, wildcard
from skidplate.ingestion import Ingestion
from skidplate.core import Assembler, LogFollower
from skidplate.diagnostics import Diagnostics


def event(serial=1, rows=None):
    now = time.time()
    rows = rows or [('PATH', 'name="/etc/ld.so.preload" nametype=NORMAL')]
    return Event([parse_line(f'type={kind} msg=audit({now:.6f}:{serial}): {body}') for kind, body in rows])


class SigmaTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temporary.name) / 'state')
        self.detector = Detector(self.store)

    def tearDown(self):
        self.store.db.close(); self.temporary.cleanup()

    def test_default_is_upstream_with_attribution_and_real_levels(self):
        match = self.detector.process(event())[0]
        self.assertEqual(match.rule, 'sigma:4b3cb710-5e83-4715-8c45-8b2b5b3e5751')
        self.assertEqual(match.severity, 'high')
        self.assertIn('Anhaus', match.authors)
        self.assertIn('https://raw.githubusercontent.com/SigmaHQ/sigma/', match.detail)
        self.assertIn('not proof', match.detail)
        self.assertFalse(any(r.rule == 'system-file-change' for r in self.detector.process(event(2,
            [('SYSCALL', 'success=yes key=sentinel_system_files exe="/usr/bin/tool"')]))))

    def test_direct_high_risk_supplements_survive_default_rebuild(self):
        alerts = self.detector.process(event(rows=[('SYSCALL',
            'arch=c000003e syscall=59 success=yes euid=0 exe="/tmp/helper"')]))
        self.assertTrue(any(a.rule == 'root-temp-exec' and a.severity == 'high' for a in alerts))
        self.assertEqual(self.detector.learning_until, 0)
        self.assertTrue(any(a.rule.startswith('sigma:') for a in alerts))
        injection = self.detector.process(event(2, [('SYSCALL',
            'arch=c000003e syscall=101 a0=4 success=yes exe="/usr/bin/debugger"')]))
        self.assertTrue(any(a.rule == 'process-injection' for a in injection))

    def test_path_creation_conditions_cannot_cross_records(self):
        unrelated = event(rows=[('PATH', 'name="/tmp/unrelated" nametype=CREATE'),
                                ('PATH', 'name="/etc/systemd/system/demo.service" nametype=NORMAL')])
        self.assertFalse(any(m['id'].startswith('1bac86') for m in self.detector.sigma.detect(unrelated)))
        created = event(2, [('PATH', 'name="/etc/systemd/system/demo.service" nametype=CREATE')])
        self.assertTrue(any(m['id'].startswith('1bac86') for m in self.detector.sigma.detect(created)))

    def test_argument_rules_require_captured_argument_data(self):
        catalog = {r['id']: r for r in self.detector.sigma.catalog}
        self.assertEqual(catalog['e497a24e-9345-4a62-9803-b06d7d7cb132']['support'], 'supported')
        self.assertIn('4096', catalog['e497a24e-9345-4a62-9803-b06d7d7cb132']['reason'])
        self.assertFalse(self.detector.sigma.detect(event(rows=[('EXECVE', 'a0="sysctl" a1="-w" a2="kernel.randomize_va_space=0"')])))

    def test_imported_auditd_rules_match_only_their_actual_selectors(self):
        engine = self.detector.sigma
        audit_rule = '977ef627-4539-4875-adf4-ed8f780c4922'
        c2_rule = 'f7158a64-6204-4d6d-868a-6e6378b467e0'
        web_rule = 'c0d3734d-330f-4a03-aae2-65dacc6a8222'
        self.assertIn(audit_rule, {m['id'] for m in engine.detect(event(rows=[
            ('PATH', 'name="/etc/audit/auditd.conf" nametype=NORMAL')]))})
        # The upstream C2 title is broad, but its actual selector is one audit
        # key. Never silently alias our connect key or classify any socket C2.
        self.assertNotIn(c2_rule, {m['id'] for m in engine.detect(event(rows=[
            ('SYSCALL', 'key=sentinel_connect arch=c000003e syscall=42')]))})
        self.assertIn(c2_rule, {m['id'] for m in engine.detect(event(rows=[
            ('SYSCALL', 'key=susp_activity')]))})
        self.assertIn(web_rule, {m['id'] for m in engine.detect(event(rows=[
            ('SYSCALL', 'arch=c000003e syscall=59 euid=33')]))})
        self.assertNotIn(web_rule, {m['id'] for m in engine.detect(event(rows=[
            ('SYSCALL', 'arch=c000003e syscall=59 euid=1000')]))})

    def test_imported_argument_rules_have_explicit_coverage_limits(self):
        catalog = {r['id']: r for r in self.detector.sigma.catalog}
        argument_rule = catalog['323ff3f5-0013-4847-bbd4-250b5edb62cc']
        self.assertEqual(argument_rule['support'], 'supported')
        self.assertIn('complete EXECVE', argument_rule['reason'])
        self.assertEqual(catalog['977ef627-4539-4875-adf4-ed8f780c4922']['support'], 'supported')

    def test_comm_and_verified_numeric_syscalls(self):
        rows = [('SYSCALL', 'arch=c000003e syscall=133 comm="insmod" exe="/usr/bin/kmod"')]
        ids = {m['id'] for m in self.detector.sigma.detect(event(rows=rows))}
        self.assertIn('106d7cbd-80ff-4985-b682-a7043e5acb72', ids)
        self.assertIn('710bdbce-495d-491d-9a8f-7d0d88d2b41e', ids)
        unknown = event(2, [('SYSCALL', 'arch=unknown syscall=133')])
        self.assertFalse(self.detector.sigma.detect(unknown))

    def test_relative_paths_use_unambiguous_captured_context(self):
        source = event(rows=[('CWD', 'cwd="/etc"'), ('PATH', 'name="ld.so.preload" nametype=NORMAL')])
        self.assertTrue(any(m['id'].startswith('4b3cb710') for m in self.detector.sigma.detect(source)))
        ambiguous = event(2, [('PATH', 'name="ld.so.preload"'), ('PATH', 'name="/etc" nametype=PARENT'),
                              ('PATH', 'name="/tmp" nametype=PARENT')])
        self.assertFalse(self.detector.sigma.detect(ambiguous))

    def test_sigma_wildcards_conditions_and_fail_closed(self):
        self.assertTrue(wildcard('/home/*/public_html/*', '/home/demo/public_html/file'))
        self.assertFalse(wildcard('/tmp/[abc]', '/tmp/a'))
        self.assertTrue(wildcard('/tmp/[abc]', '/tmp/[ABC]'))
        condition_tree('path and 1 of name_*', {'path': {}, 'name_one': {}})
        for bad in ('__import__(os)', 'selection | count() > 3', 'missing', '(' * 30):
            with self.assertRaises(Unsupported): condition_tree(bad, {'selection': {}})

    def test_rule_hash_tampering_refused(self):
        import shutil
        from skidplate.sigma_engine import ROOT
        target = Path(self.temporary.name) / 'pack'; shutil.copytree(ROOT, target)
        path = next(target.glob('*.yml')); path.write_text(path.read_text() + '\n# changed\n')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'): SigmaEngine(target)

    def test_exact_exception_counts_preserves_events_expires_and_can_disable(self):
        first = self.detector.process(event())[0]
        row = self.store.rows(alerts=True)[0]
        self.detector.ignores.save(first.rule, {'fingerprint': row[7]}, 'expected maintenance', 600)
        self.assertEqual(self.detector.process(event(2)), [])
        self.assertEqual(len(self.store.rows()), 2)
        saved = self.detector.ignores.rows()[0]
        self.assertEqual(saved[7], 1)
        self.detector.ignores.change(saved[0], 'toggle')
        self.detector.cooldown.clear()
        self.assertTrue(self.detector.process(event(3)))
        self.detector.ignores.change(saved[0], 'toggle')
        self.assertFalse(self.detector.ignores.match(first.rule, row[7], {}, time.time() + 601))
        self.detector.ignores.change(saved[0], 'delete')
        self.assertFalse(self.detector.ignores.rows())

    def test_prefix_policy_is_narrow_and_does_not_mute_sigma(self):
        criteria = dict(node='local', exe='/usr/lib/firefox/firefox', profile='firefox',
                        operation='open', denied_mask='r', name_prefix='/home/demo/.cache/')
        self.detector.ignores.save('policy-denial', criteria, 'reviewed cache denials')
        context = dict(criteria, name='/home/demo/.cache/file'); context.pop('name_prefix')
        self.assertTrue(self.detector.ignores.match('policy-denial', 'x', context, time.time()))
        for changed in ({'denied_mask': 'w'}, {'exe': '/tmp/firefox'}, {'name': '/etc/shadow'}, {'profile': 'other'}):
            self.assertFalse(self.detector.ignores.match('policy-denial', 'x', dict(context, **changed), time.time()))
        self.assertFalse(self.detector.ignores.match('sigma:example', 'x', context, time.time()))
        for prefix in ('/', '/tmp/*', '/home/../etc'):
            with self.assertRaises(ValueError): self.detector.ignores.save('policy-denial', dict(criteria, name_prefix=prefix), 'bad')


class IngestionDiagnosticsTests(unittest.TestCase):
    def test_rollback_requeues_earlier_successes_in_order(self):
        reader = Ingestion()
        first, second = event(1), event(2)
        reader.events.extend([first, second])
        class Follower:
            def poll(self, **_): return []
        seen = []
        def consume(item):
            if item is second: raise ValueError('simulate later batch failure')
            seen.append(item.identity)
        with self.assertRaises(ValueError): reader.step(Follower(), Assembler(), consume)
        reader.rollback()
        self.assertEqual(list(reader.events), [first, second])
        reader.step(Follower(), Assembler(), lambda item: seen.append(item.identity))
        reader.confirm()
        self.assertEqual(seen, [first.identity, first.identity, second.identity])

    def test_bursts_yield_without_dropping_and_batch_commits(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); store = Store(base / 'state'); detector = Detector(store)
            path = base / 'events.log'
            # Event timestamps must match between records; use one fixed time.
            when = time.time(); path.write_text(''.join(f'type=PATH msg=audit({when:.6f}:{i}): name="/example/{i}"\n'
                f'type=EOE msg=audit({when:.6f}:{i}):\n' for i in range(500)))
            follower = LogFollower(path); assembler = Assembler(); reader = Ingestion()
            commits = []
            store.db.set_trace_callback(lambda sql: commits.append(sql) if sql == 'COMMIT' else None)
            for tick in range(100):
                store.batching = True
                reader.step(follower, assembler, detector.process)
                store.batching = False; store.db.commit()
                reader.confirm()
                self.assertLessEqual(len(reader.lines), 16384)
                self.assertLessEqual(len(reader.events), 128)
                self.assertEqual(reader.uncommitted, [])
            self.assertEqual(len(store.rows(limit=1000)), 500)
            self.assertLess(len(commits), 100)
            follower.close(); store.db.close()

    def test_diagnostics_redacts_exception_value_and_private_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            diag = Diagnostics(Path(temporary))
            try:
                raise ValueError('secret audit argument that must not be written')
            except ValueError as exc:
                diag.exception_hook(type(exc), exc, exc.__traceback__)
            diag.pulse(pending_lines=2); diag.close()
            text = diag.path.read_text()
            self.assertNotIn('secret audit argument', text)
            self.assertIn('rss_kib', text)
            self.assertEqual(diag.path.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main()
