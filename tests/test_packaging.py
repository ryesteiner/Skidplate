"""Portable installation/state compatibility checks; no live user files or systemctl."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.install import install, desktop_arg, unit_arg
from skidplate.core import Store
from skidplate.paths import default_state, database_path


class PackagingTests(unittest.TestCase):
    def test_fresh_and_legacy_state_are_not_silently_merged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(default_state(root), root / 'skidplate')
            (root / 'audit-sentinel').mkdir()
            self.assertEqual(default_state(root), root / 'audit-sentinel')
            (root / 'skidplate').mkdir()
            with self.assertRaises(ValueError): default_state(root)

    def test_existing_legacy_database_is_reused_without_rename_or_reset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'state'
            store = Store(root); store.set('example', 'retained'); store.db.close()
            (root / 'skidplate.sqlite3').rename(root / 'sentinel.sqlite3')
            store = Store(root)
            self.assertEqual(store.get('example'), 'retained')
            self.assertFalse((root / 'skidplate.sqlite3').exists())
            store.db.close()
            (root / 'skidplate.sqlite3').touch()
            with self.assertRaises(ValueError): database_path(root)

    def test_install_spaces_special_chars_and_independent_payload_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary) / 'prefix space $cash %name'
            target, launcher, desktop, unit = install(prefix)
            self.assertEqual(launcher.stat().st_mode & 0o777, 0o755)
            self.assertTrue((target / 'skidplate/ui.py').is_file())
            self.assertTrue((target / 'assets/skidplate.css').is_file())
            self.assertIn('%%name', unit.read_text())
            self.assertIn('ExecStart=:', unit.read_text())
            self.assertIn('NoNewPrivileges=yes', unit.read_text())
            self.assertIn('\\\\$cash', desktop.read_text())
            result = subprocess.run(['/usr/bin/python3', '-I', str(launcher), '--version'],
                                    cwd='/', capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'Skidplate 0.2.0-prototype')
            with self.assertRaises(ValueError): install(prefix)
            old = (target / 'run.py').read_bytes()
            install(prefix, upgrade=True)
            backups = list((prefix / 'share').glob('skidplate.backup-*'))
            self.assertEqual(len(backups), 1)
            self.assertEqual((backups[0] / 'run.py').read_bytes(), old)

    def test_installer_rejects_root_symlinks_writable_dirs_and_control_chars(self):
        with patch('tools.install.os.geteuid', return_value=0), self.assertRaises(ValueError): install('/tmp/not-created')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'actual').mkdir()
            (root / 'link').symlink_to(root / 'actual', target_is_directory=True)
            with self.assertRaises(ValueError): install(root / 'link/child')
            self.assertFalse((root / 'actual/child').exists())
            writable = root / 'writable'; writable.mkdir(); writable.chmod(0o777)
            with self.assertRaises(ValueError): install(writable)
            with self.assertRaises(ValueError): desktop_arg('/tmp/bad\nExec=anything')
            with self.assertRaises(ValueError): unit_arg('/tmp/bad\nExecStart=anything')


if __name__ == '__main__':
    unittest.main()
