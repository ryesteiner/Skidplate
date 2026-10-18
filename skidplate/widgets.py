"""Skidplate's local GTK presentation widgets. All evidence uses plain text."""
from __future__ import annotations

import gi
import math
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib, Pango
from .highlighting import set_evidence, LEGEND


def text_label(text="", style=None):
    label = Gtk.Label(label=text, xalign=0)
    label.set_line_wrap(True)
    label.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
    label.set_max_width_chars(48)
    if style:
        label.get_style_context().add_class(style)
    return label


def flow(items, maximum=4):
    box = Gtk.FlowBox()
    box.set_selection_mode(Gtk.SelectionMode.NONE)
    box.set_min_children_per_line(1)
    box.set_max_children_per_line(maximum)
    box.set_column_spacing(10)
    box.set_row_spacing(10)
    for item in items:
        box.add(item)
    return box


class StatusCard(Gtk.Box):
    def __init__(self, title):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.set_border_width(4)
        self.set_size_request(190, -1)
        self.get_style_context().add_class("instrument")
        self.pack_start(text_label(title.upper(), "eyebrow"), False, False, 0)
        self.value = text_label("—", "readout")
        self.pack_start(self.value, False, False, 0)
        self.detail = text_label("Waiting for data", "muted")
        self.pack_start(self.detail, False, False, 0)

    def update(self, value, detail, level="info"):
        self.value.set_text(str(value))
        self.detail.set_text(detail)
        context = self.get_style_context()
        for style in ("ok", "warning", "danger", "info"):
            context.remove_class(style)
        context.add_class(level)


def cluster_layout(width, percent, focus):
    """Responsive unequal-size gauge geometry, shared by drawing and height allocation."""
    width = max(280, width)
    scale = min(120, max(80, percent)) / 100
    focus = focus if focus in {'network', 'attention', 'behavior'} else 'network'
    others = [name for name in ('attention', 'network', 'behavior') if name != focus]
    if width >= 760:
        radius = min(110 * scale, width * .13)
        y = 45 + radius
        lower = y + radius + 70
        gauges = [(others[0], width * .18, y, radius * .72),
                  (focus, width * .5, y, radius),
                  (others[1], width * .82, y, radius * .72),
                  ('rules', width * .18, lower, 46 * scale)]
        baseline = lower + 12
        height = math.ceil(max(lower + 46 * scale + 20, baseline + 45))
    else:
        radius = min(95 * scale, width / 4 - 17)
        small = radius * .72
        y = 40 + radius
        second = y + radius + small + 24
        gauges = [(focus, width * .27, y, radius),
                  (others[0], width * .75, y, small),
                  (others[1], width * .27, second, small),
                  ('rules', width * .75, second, small)]
        baseline = second + small + 62
        height = math.ceil(baseline + 45)
    return gauges, baseline, height


class InstrumentCluster(Gtk.DrawingArea):
    """One continuous dashboard fascia, with real counters instead of safety scores."""
    def __init__(self):
        super().__init__()
        self.set_size_request(280, 430)
        self.set_hexpand(True)
        self.total = self.high = self.enabled = 0
        self.rules = 1
        self.available = self.quiet = False
        self.network = None
        self.network_partial = True
        self.behavior = 0
        self.focus, self.size_percent = 'network', 100
        self.requested_height = 430
        self.connect('size-allocate', self.allocate_cluster)
        self.connect('draw', self.draw_cluster)
        self.set_tooltip_text('Processed-event total persists across retention and restarts. '
            'Starts with available history; old purged events cannot be reconstructed. '
            'Reimported events whose IDs expired can count again. Dials are counts, not a safety verdict.')

    def update(self, total, high, enabled, rules, available, quiet):
        self.total, self.high = max(0, int(total)), max(0, int(high))
        self.enabled, self.rules = max(0, int(enabled)), max(1, int(rules))
        self.available, self.quiet = bool(available), bool(quiet)
        self.get_accessible().set_name(f'Skidplate instruments: {self.total} processed events; '
            f'{self.high} important groups awaiting review; {self.enabled} of {self.rules} rules enabled; '
            f'log input {"readable" if self.available else "unavailable"}.')
        self.queue_draw()

    def set_layout(self, focus, percent):
        self.focus = focus if focus in {'network', 'attention', 'behavior'} else 'network'
        self.size_percent = min(120, max(80, int(percent)))
        self.allocate_cluster(self, self.get_allocation())
        self.queue_draw()

    def allocate_cluster(self, widget, allocation):
        _, _, height = cluster_layout(allocation.width, self.size_percent, self.focus)
        if height != self.requested_height:
            self.requested_height = height
            self.set_size_request(280, height)

    def set_network(self, count, partial):
        self.network = None if count is None else max(0, int(count))
        self.network_partial = bool(partial)
        self.set_tooltip_text('Network = visible established TCP + connected UDP in this namespace, including loopback. '
            'A star means partial visibility; ? means unavailable/stale. Gauge caps at 128+, exact number remains shown. '
            'Behavior = live persistence/behavior groups last seen within 24h, including reviewed groups. '
            'Processed total persists across retention; old purged records cannot be recovered.')
        self.get_accessible().set_description(f'Active network sockets: {self.network if self.network is not None else "unknown"}; '
            f'partial visibility: {self.network_partial}; behavior groups in 24h: {self.behavior}.')
        self.queue_draw()

    def set_behavior(self, count):
        self.behavior = max(0, int(count))
        self.queue_draw()

    @staticmethod
    def lettering(cr, text, x, y, size=12, color=(0.65, 0.73, 0.77)):
        cr.select_font_face('monospace', 0, 1)
        cr.set_font_size(size)
        cr.set_source_rgb(*color)
        extent = cr.text_extents(text)
        cr.move_to(x - extent.width / 2 - extent.x_bearing, y)
        cr.show_text(text)

    def dial(self, cr, x, y, radius, value, maximum, title, unit, color):
        missing = value is None
        display = '?' if missing else str(value)
        value = 0 if missing else max(0, int(value))
        start, sweep = math.radians(140), math.radians(260)
        cr.set_source_rgb(0.02, 0.03, 0.04)
        cr.arc(x, y, radius + 8, 0, math.tau); cr.fill()
        cr.set_source_rgb(0.3, 0.34, 0.37)
        cr.set_line_width(2)
        cr.arc(x, y, radius + 7, 0, math.tau); cr.stroke()
        cr.set_source_rgb(0.16, 0.21, 0.24)
        cr.set_line_width(5)
        cr.arc(x, y, radius - 4, start, start + sweep); cr.stroke()
        if value:
            cr.set_source_rgb(*color)
            cr.arc(x, y, radius - 4, start, start + sweep * min(value / maximum, 1)); cr.stroke()
        for tick in range(21):
            angle = start + sweep * tick / 20
            outer, inner = radius * .88, radius * (.77 if tick % 5 == 0 else .83)
            cr.set_source_rgb(0.6, 0.65, 0.67)
            cr.set_line_width(2 if tick % 5 == 0 else 1)
            cr.move_to(x + math.cos(angle) * inner, y + math.sin(angle) * inner)
            cr.line_to(x + math.cos(angle) * outer, y + math.sin(angle) * outer); cr.stroke()
        angle = start + sweep * min(value / maximum, 1)
        cr.set_line_width(3)
        cr.set_source_rgb(*color)
        if not missing:
            cr.move_to(x, y); cr.line_to(x + math.cos(angle) * radius * .68, y + math.sin(angle) * radius * .68); cr.stroke()
        cr.arc(x, y, 5, 0, math.tau); cr.fill()
        self.lettering(cr, display, x, y + radius * .35, min(30, max(14, radius * .26)), (0.94, 0.94, 0.86))
        self.lettering(cr, title, x, y - radius * .35, min(11, max(7, radius * .12)))
        self.lettering(cr, unit, x, y + radius * .72, min(9, max(6, radius * .09)))

    def draw_cluster(self, widget, cr):
        width, height = widget.get_allocated_width(), widget.get_allocated_height()
        cr.set_source_rgb(0.035, 0.045, 0.055); cr.paint()
        cr.set_source_rgb(0.22, 0.27, 0.3); cr.set_line_width(2)
        cr.rectangle(2, 2, max(1, width - 4), max(1, height - 4)); cr.stroke()
        self.lettering(cr, 'SKIDPLATE  /  LOCAL INSTRUMENTS', width / 2, 26, 11)
        gauges, baseline, _ = cluster_layout(width, self.size_percent, self.focus)
        values = {
            'attention': (self.high, 20, 'ATTENTION', 'GROUPS / 20+', (.95, .38, .26)),
            'network': (self.network, 128, 'NETWORK', 'ACTIVE / 128+' + ('*' if self.network_partial else ''), (.36, .8, .7)),
            'behavior': (self.behavior, 10, 'BEHAVIOR', '24H GROUPS / 10+', (.95, .68, .28)),
            'rules': (self.enabled, self.rules, 'RULES', f'ENABLED / {self.rules}', (.38, .76, .86)),
        }
        for name, x, y, radius in gauges:
            self.dial(cr, x, y, radius, *values[name])
        digits = f'{min(self.total, 99999999):08d}'
        for index, digit in enumerate(digits):
            x = width / 2 - 100 + index * 25
            cr.set_source_rgb(0.12, 0.15, 0.17); cr.rectangle(x, baseline - 25, 23, 32); cr.fill()
            cr.set_source_rgb(0.35, 0.38, 0.39); cr.set_line_width(1)
            cr.rectangle(x, baseline - 25, 23, 32); cr.stroke()
            cr.set_source_rgb(0.025, 0.03, 0.035)
            cr.move_to(x, baseline - 9); cr.line_to(x + 23, baseline - 9); cr.stroke()
            self.lettering(cr, digit, x + 11, baseline, 23, (0.94, 0.89, 0.73))
        self.lettering(cr, 'EVENTS PROCESSED' + (f'  /  {self.total:,}' if self.total > 99999999 else ''), width / 2, baseline + 30, 10)
        lamp = (0.95, 0.63, 0.23) if not self.available or self.quiet else (0.4, 0.78, 0.58)
        label = 'LOG INPUT LOST' if not self.available else 'INPUT QUIET' if self.quiet else 'LOG INPUT READABLE'
        self.lettering(cr, label, width / 2, baseline - 38, 9, lamp)
        return False


class HistoryPanel(Gtk.Box):
    """Responsive list/detail split retaining selection and reading position."""
    def __init__(self, model, columns, key_index, fraction=0.65):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.model, self.columns, self.key_index = model, columns, key_index
        self.fraction = min(0.85, max(0.2, fraction))
        self.refreshing = False
        self.positioning = False
        self.last_height = 0
        self.row_filter = lambda row: True
        self.detail_formatter = None
        self.search = Gtk.SearchEntry(placeholder_text="Filter latest 500 rows…")
        self.pack_start(self.search, False, False, 0)
        self.filtered = model.filter_new()
        self.filtered.set_visible_func(lambda m, row, _: self.row_filter(m[row]) and
            self.search.get_text().casefold() in " ".join(str(x) for x in m[row]).casefold(), None)
        self.search.connect("search-changed", lambda _: self.filtered.refilter())
        self.view = Gtk.TreeView(model=self.filtered)
        self.view.set_hexpand(True)
        self.view.set_vexpand(True)
        for index, title in enumerate(columns):
            renderer = Gtk.CellRendererText(ellipsize=Pango.EllipsizeMode.END)
            renderer.set_padding(12, 8)
            column = Gtk.TreeViewColumn(title, renderer, text=index)
            column.set_resizable(True)
            column.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
            column.set_fixed_width(110 if index < 4 else 220)
            column.set_min_width(50)
            column.set_expand(title in {"Alert", "Executable"})
            self.view.append_column(column)
        self.list_scroll = Gtk.ScrolledWindow()
        self.list_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.list_scroll.add(self.view)
        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        header = Gtk.Box(spacing=6)
        header.set_margin_start(16)
        header.set_margin_end(16)
        header.set_margin_top(8)
        header.pack_start(text_label("EVIDENCE  ·  drag the divider above to resize", "eyebrow"), True, True, 0)
        copy = Gtk.Button(label="Copy")
        copy.connect("clicked", self.copy_details)
        header.pack_end(copy, False, False, 0)
        detail_box.pack_start(header, False, False, 0)
        legend = text_label(LEGEND, 'muted')
        legend.set_margin_start(16)
        legend.set_margin_end(16)
        detail_box.pack_start(legend, False, False, 0)
        self.details = Gtk.TextView(editable=False, cursor_visible=True)
        self.details.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.details.set_left_margin(20)
        self.details.set_right_margin(20)
        self.details.set_top_margin(16)
        self.details.set_bottom_margin(16)
        set_evidence(self.details.get_buffer(), "Select a row to inspect its complete stored evidence.")
        self.detail_scroll = Gtk.ScrolledWindow()
        self.detail_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.detail_scroll.add(self.details)
        detail_box.pack_start(self.detail_scroll, True, True, 0)
        self.split = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        self.split.set_wide_handle(True)
        self.split.pack1(self.list_scroll, True, False)
        self.split.pack2(detail_box, True, False)
        self.split.connect("size-allocate", self.allocate_split)
        self.split.connect("notify::position", self.moved_split)
        self.pack_start(self.split, True, True, 0)
        self.view.get_selection().connect("changed", self.selected)

    def allocate_split(self, widget, allocation):
        if allocation.height > 1 and allocation.height != self.last_height:
            self.last_height = allocation.height
            self.positioning = True
            widget.set_position(int(allocation.height * self.fraction))
            self.positioning = False

    def moved_split(self, widget, _):
        if not self.positioning and self.last_height > 1:
            self.fraction = min(0.85, max(0.2, widget.get_position() / self.last_height))

    def selected_id(self):
        model, row = self.view.get_selection().get_selected()
        return model[row][self.key_index] if row is not None else None

    def selected(self, selection):
        if self.refreshing:
            return
        model, row = selection.get_selected()
        if row is None:
            set_evidence(self.details.get_buffer(), "Select a row to inspect its evidence and investigation context.")
            return
        if row is not None:
            text = (self.detail_formatter(model[row]) if self.detail_formatter else
                    "\n\n".join(f"{label}: {model[row][i]}" for i, label in enumerate(self.columns)))
            buffer = self.details.get_buffer()
            if buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True) != text:
                set_evidence(buffer, text)

    def select_id(self, identity):
        for row in self.filtered:
            if row[self.key_index] == identity:
                self.view.get_selection().select_path(row.path)
                return True
        return False

    def update(self, rows):
        if [list(row) for row in self.model] == rows:
            return
        selected = self.selected_id()
        list_position = self.list_scroll.get_vadjustment().get_value()
        detail_position = self.detail_scroll.get_vadjustment().get_value()
        self.refreshing = True
        self.model.clear()
        for row in rows:
            self.model.append(row)
        found = selected is not None and self.select_id(selected)
        self.refreshing = False
        if found:
            self.selected(self.view.get_selection())
        elif selected is not None:
            set_evidence(self.details.get_buffer(), "This row is no longer in the displayed history or current filter.")
        def restore():
            self.list_scroll.get_vadjustment().set_value(list_position)
            if found:
                self.detail_scroll.get_vadjustment().set_value(detail_position)
            return False
        GLib.idle_add(restore)

    def copy_details(self, _):
        from gi.repository import Gdk
        buffer = self.details.get_buffer()
        Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(
            buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True), -1)
