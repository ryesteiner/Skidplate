"""Evidence presentation must not interpret markup, hide text or shift Unicode."""
import unittest

from skidplate.highlighting import spans, set_evidence, MAX_SCAN, MAX_TAGS


class HighlightTests(unittest.TestCase):
    def test_key_fields_and_unicode_offsets(self):
        text = ('é → WHAT HAPPENED\nWHAT HAPPENED\nOriginating login: 1000 (demo)\n'
                'Executable: /usr/bin/sudo\nPID=123; parent PID=12; session=2\n'
                'Recorded connect destination: [2001:db8::1]:443 · result=no\n')
        pieces = [(kind, text[start:end]) for kind, start, end in spans(text)]
        for expected in [('heading', 'WHAT HAPPENED'), ('user', '1000 (demo)'),
                         ('path', '/usr/bin/sudo'), ('process', '123'), ('process', '12'),
                         ('endpoint', '[2001:db8::1]:443'), ('failure', 'no')]:
            self.assertIn(expected, pieces)

    def test_gtk_buffer_keeps_markup_literal_and_resets_stale_tags(self):
        import gi
        gi.require_version('Gtk', '3.0')
        from gi.repository import Gtk
        buffer = Gtk.TextBuffer()
        text = '<b>literal</b>\nOriginating login: 1000 (demo)\nExecutable: /tmp/a\nresult=yes'
        set_evidence(buffer, text)
        self.assertEqual(buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True), text)
        tag = buffer.get_tag_table().lookup('evidence-path')
        self.assertTrue(buffer.get_iter_at_offset(text.index('/tmp/a')).has_tag(tag))
        set_evidence(buffer, 'no selection')
        self.assertFalse(buffer.get_start_iter().has_tag(tag))
        self.assertEqual(buffer.get_tag_table().get_size(), 7)

    def test_work_is_bounded_without_truncating_evidence(self):
        text = 'exe=/tmp/file; auid=1000; result=yes\n' * 20000
        found = spans(text)
        self.assertLessEqual(len(found), MAX_TAGS)
        self.assertTrue(all(0 <= start < end <= MAX_SCAN for _, start, end in found))


if __name__ == '__main__':
    unittest.main()
