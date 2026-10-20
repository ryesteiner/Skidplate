"""Offline helper tests: ordinary-user temporary files only, no host ACL changes."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('log_access_helper',
    Path(__file__).resolve().parents[1] / 'deploy/log-access-button/helper.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class ACLTests(unittest.TestCase):
    def test_mask_does_not_reenable_other_users_or_groups(self):
        result = helper.updated_acl('user::rw-\nuser:2000:rw-\ngroup::rwx\ngroup:3000:rw-\nmask::---\nother::---\n', 1000, 4)
        self.assertIn('user:1000:r--\n', result)
        self.assertIn('user:2000:---\n', result)
        self.assertIn('group::---\n', result)
        self.assertIn('group:3000:---\n', result)
        self.assertIn('mask::r--\n', result)
        self.assertEqual(result, helper.updated_acl(result, 1000, 4))

    def test_existing_effective_rights_are_preserved(self):
        result = helper.updated_acl('user::rwx\nuser:2000:rwx\ngroup::r-x\nmask::r-x\nother::---\n', 1000, 1)
        self.assertIn('user:2000:r-x\n', result)
        self.assertIn('group::r-x\n', result)
        self.assertIn('user:1000:--x\n', result)

    def test_basic_acl_gains_named_reader(self):
        result = helper.updated_acl('user::rw-\ngroup::---\nother::---\n', 1000, 4)
        self.assertIn('user::rw-\n', result)
        self.assertIn('user:1000:r--\n', result)
        self.assertIn('other::---\n', result)

    def test_malformed_acl_is_rejected(self):
        for text in ('user::rw-\n', 'user::rw-\ngroup::---\nother::---\nmask:123:rwx',
                     'user::rw-\ngroup::---\nother::---\nuser:1000:r--\nuser:1000:rw-'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                helper.updated_acl(text, 1000, 4)

    def test_native_acl_uses_only_temporary_file(self):
        with tempfile.TemporaryFile() as file:
            os.fchmod(file.fileno(), 0o600)
            # A user namespace may map only the current UID. An unmapped
            # numeric qualifier causes kernel EINVAL even for an otherwise
            # valid ACL. Mask isolation is exercised separately above.
            helper.ACL().grant(file.fileno(), os.getuid(), 4)
            self.assertEqual(os.fstat(file.fileno()).st_mode & 0o777, 0o640)
            helper.ACL().grant(file.fileno(), os.getuid(), 4)
            self.assertEqual(os.fstat(file.fileno()).st_mode & 0o777, 0o640)

    def test_service_rejects_system_users_before_opening(self):
        for uid in (0, 999, 65534):
            with self.subTest(uid=uid), patch.object(helper.os, 'open') as opened:
                with self.assertRaises(PermissionError):
                    helper.grant_logs(uid)
                opened.assert_not_called()

    def test_metadata_rejects_symlinks_hardlinks_and_writable_files(self):
        import stat
        from types import SimpleNamespace
        for mode, uid, links in ((stat.S_IFLNK | 0o777, 0, 1),
                                 (stat.S_IFREG | 0o620, 0, 1),
                                 (stat.S_IFREG | 0o600, 1000, 1),
                                 (stat.S_IFREG | 0o600, 0, 2)):
            with self.subTest(mode=mode), patch.object(helper.os, 'fstat',
                return_value=SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links)):
                with self.assertRaises(PermissionError):
                    helper.safe_metadata(3, False)


if __name__ == '__main__':
    unittest.main()
