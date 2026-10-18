"""GTK integration checks; run with a disposable display (e.g. Broadway)."""
import unittest

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib
from skidplate.widgets import HistoryPanel


class HistoryWidgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Gtk.init_check()[0]:
            raise unittest.SkipTest("GTK display unavailable; headless core tests still run")

    def setUp(self):
        self.model = Gtk.ListStore(int, str)
        self.panel = HistoryPanel(self.model, ["ID", "Evidence"], 0)
        self.window = Gtk.Window()
        self.window.add(self.panel)
        self.window.show_all()
        self.pump()

    def tearDown(self):
        self.window.destroy()
        self.pump()

    @staticmethod
    def pump():
        for _ in range(30):
            if not Gtk.events_pending():
                break
            Gtk.main_iteration_do(False)

    def test_selection_and_full_plain_text_survive_new_rows(self):
        evidence = '<b>literal, not markup</b>\n' + "full evidence " * 500
        self.panel.update([[1, evidence]])
        self.assertTrue(self.panel.select_id(1))
        self.pump()
        buffer = self.panel.details.get_buffer()
        self.assertIn(evidence, buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True))
        self.panel.update([[2, "new alert"], [1, evidence]])
        self.pump()
        self.assertEqual(self.panel.selected_id(), 1)
        self.assertIn(evidence, buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True))
        self.panel.search.set_text("new alert")
        self.panel.filtered.refilter()
        self.assertFalse(self.panel.select_id(1))

    def test_resizing_preserves_divider_proportion(self):
        self.panel.fraction = 0.6
        allocation = self.panel.split.get_allocation()
        allocation.height = 500
        self.panel.allocate_split(self.panel.split, allocation)
        self.assertAlmostEqual(self.panel.split.get_position() / 500, 0.6, delta=0.02)
        allocation.height = 800
        self.panel.allocate_split(self.panel.split, allocation)
        self.assertAlmostEqual(self.panel.split.get_position() / 800, 0.6, delta=0.02)
