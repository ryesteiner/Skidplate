"""GTK3 dashboard and StatusNotifier/AppIndicator integration."""
from __future__ import annotations

import argparse
import collections
import fcntl
import json
import os
from pathlib import Path
import stat
import sqlite3
import tempfile
import threading
import time

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
gi.require_version("Notify", "0.7")
from gi.repository import Gtk, GLib, Gdk, Gio, AyatanaAppIndicator3 as Indicator, Notify

from .core import Assembler, Detector, Event, LogFollower, RULES, Store, clean, network_watchlist, parse_line
from .resolver import ResolverFollower
from .widgets import InstrumentCluster, HistoryPanel, StatusCard, flow, text_label
from .behavior import IMPORTANT_RULES, guidance, behavior_groups
from .investigate import snapshot, containment_guidance
from .network import NetworkSampler
from .evidence import local_accounts, user_label
from .highlighting import set_evidence
from .paths import default_state
from . import __version__

ROOT = Path(__file__).resolve().parent.parent


def stamp(value):
    try:
        return time.strftime("%m-%d %H:%M:%S", time.localtime(value))
    except (ValueError, OverflowError, OSError):
        return "Invalid time"


class Dashboard:
    def __init__(self, source: Path, state: Path, demo=False, background=False):
        self.store = Store(state)
        self.lockfd = os.open(state / "app.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(self.lockfd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise PermissionError("Unsafe instance lock")
        try:
            fcntl.flock(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Skidplate is already running for this state directory")
        self.demo = demo
        self.engine = Detector(self.store)
        try:
            self.engine.auth_threshold = min(30, max(3, int(self.store.get("auth_threshold", "5"))))
            self.engine.auth_window = min(3600, max(60, int(self.store.get("auth_window", "300"))))
        except ValueError:
            pass
        self.follower = LogFollower(source)
        self.assembler = Assembler()
        self.started = time.time()
        self.last_event = None
        self.last_live_received = None
        self.quiet_notified = False
        self.parse_skipped = 0
        self.skip_notified = False
        self.notice_times = collections.deque(maxlen=6)
        self.snoozed_until = 0
        self.refresh_at = 0
        self.unavailable_notified = False
        self.monitor_error = ""
        self.notifications = self.store.get("notifications", "1") == "1"
        self.high_only = self.store.get("high_only", "1") == "1"
        self.resolver = ResolverFollower() if not demo and self.store.get("dns_telemetry", "1") == "1" else None
        self.resolver_notified = False
        Notify.init("Skidplate")
        self.history_panels = []
        self.timeline_key = None
        self.window_narrow = None
        self.access_request = None
        self.focused_popups = self.store.get("focused_popups", "1") == "1"
        self.inspection_busy = False
        self.network_sampler = None if demo else NetworkSampler()
        self.network_snapshot = None
        self.network_rendered = None
        self.network_rows_by_key = {}
        self.behavior_key = None
        self.alert_pin = None
        self.local_accounts = local_accounts()

        self.window = Gtk.Window(title="Skidplate" + (" · DEMO" if demo else ""))
        self.window.get_style_context().add_class("skidplate")
        self.css = Gtk.CssProvider()
        self.css.load_from_path(str(ROOT / "assets/skidplate.css"))
        Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), self.css,
                                                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        self.window.set_default_size(self.saved_int("window_width", 1180, 480, 2400),
                                     self.saved_int("window_height", 800, 400, 1800))
        self.window.connect("delete-event", self.hide)
        self.window.set_icon_from_file(str(ROOT / "assets/shield.svg"))
        container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        container.set_border_width(20)
        self.window.add(container)
        header = Gtk.Box(spacing=12)
        emblem = Gtk.Image.new_from_file(str(ROOT / "assets/shield.svg"))
        header.pack_start(emblem, False, False, 0)
        heading = text_label("SKIDPLATE", "brand")
        header.pack_start(heading, True, True, 0)
        container.pack_start(header, False, False, 0)
        subtitle = text_label("UNDER THE SURFACE. ON YOUR SIDE.  ·  Local security telemetry", "muted")
        container.pack_start(subtitle, False, False, 0)
        self.health = Gtk.Label(label="Connecting to log source…")
        self.health.set_xalign(0)
        self.health.set_line_wrap(True)
        self.health.set_line_wrap_mode(2)
        self.health.set_max_width_chars(64)
        self.health.get_style_context().add_class("health-strip")
        self.health.set_selectable(True)
        container.pack_start(self.health, False, False, 0)

        self.stats = Gtk.Label()
        self.stats.set_xalign(0)
        self.stats.set_line_wrap(True)
        self.stats.set_line_wrap_mode(2)
        self.stats.set_max_width_chars(70)
        self.stats.get_style_context().add_class("muted")
        container.pack_start(self.stats, False, False, 0)
        notebook = Gtk.Stack()
        self.pages = notebook
        notebook.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        notebook.set_transition_duration(120)
        notebook.set_homogeneous(False)
        container.pack_start(notebook, True, True, 0)
        self.navigation = Gtk.StackSwitcher(stack=notebook)
        self.navigation.set_halign(Gtk.Align.CENTER)
        self.navigation.get_style_context().add_class('switch-panel')
        self.compact_navigation = Gtk.ComboBoxText()
        self.compact_navigation.set_halign(Gtk.Align.CENTER)
        self.compact_navigation.get_style_context().add_class('switch-selector')
        for name, title in (("overview", "Overview"), ("alerts", "Alerts"),
                            ("events", "Events"), ("network", "Network"),
                            ("behavior", "Behavior"), ("rules", "Rules & access")):
            self.compact_navigation.append(name, title)
        self.compact_navigation.set_active_id("overview")
        self.compact_navigation.connect("changed", lambda widget:
            notebook.set_visible_child_name(widget.get_active_id() or "overview"))
        notebook.connect("notify::visible-child-name", lambda *_:
            self.compact_navigation.set_active_id(notebook.get_visible_child_name()))
        # Hidden navigation must not be re-shown by show_all when opening tray.
        self.navigation.set_no_show_all(True)
        self.compact_navigation.set_no_show_all(True)
        container.pack_start(self.navigation, False, False, 0)
        container.reorder_child(self.navigation, 3)
        container.pack_start(self.compact_navigation, False, False, 0)
        container.reorder_child(self.compact_navigation, 4)
        self.window.connect("size-allocate", self.resize_window)
        notebook.add_titled(self.overview(), "overview", "Overview")
        self.alert_model = Gtk.ListStore(int, str, str, str, str, str, str, str, int, str, str)
        self.event_model = Gtk.ListStore(*([str] * 15))
        alerts_tab = self.make_table(self.alert_model,
            ["ID", "Last seen", "Severity", "Rule", "Alert", "Evidence", "Reviewed", "Notifications", "Repeats", "First seen"])
        self.alert_scope = Gtk.ComboBoxText()
        for identity, label in (("important", "Important signals"), ("high", "All High alerts"), ("all", "All alerts")):
            self.alert_scope.append(identity, label)
        self.alert_scope.set_active_id("important")
        self.alert_scope.connect("changed", lambda _: self.history_panels[0].filtered.refilter())
        alerts_tab.pack_start(self.alert_scope, False, False, 0)
        alerts_tab.reorder_child(self.alert_scope, 0)
        self.history_panels[0].row_filter = lambda row: (
            self.alert_scope.get_active_id() == "all" or
            row[2] == "HIGH" and (self.alert_scope.get_active_id() == "high" or row[3] in IMPORTANT_RULES))
        self.history_panels[0].detail_formatter = self.alert_details
        self.alert_view.connect('row-activated', self.inspect_selected)
        inspect = Gtk.Button(label="Inspect process & connections…")
        inspect.connect("clicked", self.inspect_selected)
        alerts_tab.pack_start(inspect, False, False, 0)
        alerts_tab.reorder_child(inspect, 1)
        self.snooze_duration = Gtk.ComboBoxText()
        for label in ("10 minutes", "1 hour", "24 hours"):
            self.snooze_duration.append_text(label)
        self.snooze_duration.set_active(1)
        snooze_selected = Gtk.Button(label="Snooze matching selected event")
        snooze_selected.connect("clicked", self.snooze_selected)
        clear_snoozes = Gtk.Button(label="Clear event snoozes")
        clear_snoozes.connect("clicked", self.clear_event_snoozes)
        actions = flow([self.snooze_duration, snooze_selected, clear_snoozes], maximum=3)
        alerts_tab.pack_start(actions, False, False, 0)
        notebook.add_titled(alerts_tab, "alerts", "Alerts")
        notebook.add_titled(self.make_table(self.event_model,
            ["Time", "Types", "Login UID", "UID", "Account", "Address", "Executable", "Result", "Audit key", "Audit event",
             "PID", "Parent PID", "Effective UID", "Session", "Host"]), "events", "Events")
        self.history_panels[1].detail_formatter = self.event_details
        notebook.add_titled(self.network_page(), "network", "Network")
        notebook.add_titled(self.behavior_page(), "behavior", "Behavior")
        notebook.add_titled(self.controls(source), "rules", "Rules & access")
        for button in self.navigation.get_children():
            label = button.get_child()
            if isinstance(label, Gtk.Label):
                label.set_text(label.get_text().upper())

        acknowledge = Gtk.Button(label="Mark selected alert reviewed")
        acknowledge.connect("clicked", self.acknowledge)
        open_rules = Gtk.Button(label="Refresh history")
        open_rules.connect("clicked", lambda _: self.refresh())
        close = Gtk.Button(label="Hide to tray")
        close.connect("clicked", self.hide)
        footer = flow([acknowledge, open_rules, close], maximum=3)
        container.pack_end(footer, False, False, 0)

        self.indicator = Indicator.Indicator.new("skidplate" + ("-demo" if demo else ""),
            str(ROOT / "assets/shield-warning.svg"), Indicator.IndicatorCategory.SYSTEM_SERVICES)
        self.indicator.set_status(Indicator.IndicatorStatus.ACTIVE)
        self.indicator.set_title("Skidplate")
        menu = Gtk.Menu()
        self.menu_status = Gtk.MenuItem(label="Connecting…")
        self.menu_status.set_sensitive(False)
        menu.append(self.menu_status)
        for title, handler in [("Open Skidplate dashboard", self.show),
                               ("Snooze notifications for 10 minutes", self.snooze),
                               ("Quit Skidplate", self.quit)]:
            item = Gtk.MenuItem(label=title)
            item.connect("activate", handler)
            menu.append(item)
        menu.show_all()
        self.indicator.set_menu(menu)
        self.window.show_all()
        if background:
            self.window.hide()
        self.refresh()
        GLib.timeout_add(500, self.tick)

    def make_table(self, model, columns):
        index = len(self.history_panels)
        panel = HistoryPanel(model, columns, 0 if model is self.alert_model else 9,
            self.saved_int(f"detail_split_{index}", 65, 20, 85) / 100)
        self.history_panels.append(panel)
        if model is self.alert_model:
            self.alert_view = panel.view
        return panel

    def saved_int(self, key, default, minimum, maximum):
        try:
            return min(maximum, max(minimum, int(self.store.get(key, str(default)))))
        except ValueError:
            return default

    def resize_window(self, _, allocation):
        narrow = allocation.width < 940
        if narrow != self.window_narrow:
            self.window_narrow = narrow
            self.navigation.set_visible(not narrow)
            self.compact_navigation.set_visible(narrow)

    def overview(self):
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        content.set_border_width(16)
        content.pack_start(text_label("INSTRUMENT CLUSTER  /  LOCAL TELEMETRY", "eyebrow"), False, False, 0)
        self.instruments = {name: StatusCard(name) for name in
                            ("Monitoring", "Important signals", "Behavior rules", "Noise control")}
        self.cluster = InstrumentCluster()
        content.pack_start(self.cluster, False, False, 0)
        shortcuts = []
        for name, title in [('network', 'Open network monitor'), ('behavior', 'Open behavior recorder'), ('alerts', 'Review alerts')]:
            button = Gtk.Button(label=title)
            button.connect('clicked', lambda _, page=name: self.pages.set_visible_child_name(page))
            shortcuts.append(button)
        content.pack_start(flow(shortcuts, maximum=3), False, False, 0)
        self.network_summary = text_label('Network snapshot pending…', 'muted')
        content.pack_start(self.network_summary, False, False, 0)
        self.protection = {name: StatusCard(name) for name in
                           ("Host", "Network", "Correlation", "DNSSEC")}
        diagnostics = Gtk.Expander(label="Under the hood · coverage and source diagnostics")
        diagnostic_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        diagnostic_box.set_border_width(12)
        checks = flow([*self.instruments.values(), *self.protection.values()], maximum=4)
        checks.set_homogeneous(True)
        checks.get_style_context().add_class("system-checks")
        diagnostic_box.pack_start(checks, False, False, 0)
        self.overview_health = text_label("Checking local sources…", "muted")
        self.overview_health.set_selectable(True)
        diagnostic_box.pack_start(self.overview_health, False, False, 0)
        diagnostics.add(diagnostic_box)
        content.pack_start(diagnostics, False, False, 0)
        content.pack_start(text_label("CHECK ENGINE  /  PRIORITY ALERTS", "section-title"), False, False, 0)
        self.priority = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        content.pack_start(self.priority, False, False, 0)
        content.pack_start(text_label("EVENT RECORDER", "section-title"), False, False, 0)
        content.pack_start(text_label("Behavior rules link specific ordered events. This timeline is chronological; nearby events are not automatically related.", "muted"), False, False, 0)
        self.timeline = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        content.pack_start(self.timeline, False, False, 0)
        content.pack_start(text_label("A readable source is not a safety verdict. Findings need review and missing telemetry limits coverage.", "muted"), False, False, 0)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add(content)
        return scroll

    def network_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(16)
        box.pack_start(text_label('NETWORK PIT WALL', 'section-title'), False, False, 0)
        box.pack_start(text_label('Active = established TCP + connected UDP in this network namespace. PID/application columns show observed socket holders where permissions allow. Select a row for executable paths and limitations; shared sockets can have several holders.', 'muted'), False, False, 0)
        self.network_status = text_label('Waiting for network snapshot…', 'muted')
        self.network_status.set_selectable(True)
        box.pack_start(self.network_status, False, False, 0)
        self.network_scope = Gtk.ComboBoxText()
        for name, label in [('active', 'Active sockets'), ('all', 'All visible TCP/UDP sockets'), ('listen', 'Listening TCP sockets')]:
            self.network_scope.append(name, label)
        self.network_scope.set_active_id('active')
        refresh = Gtk.Button(label='Refresh network snapshot')
        refresh.set_sensitive(not self.demo)
        refresh.connect('clicked', lambda *_: self.network_sampler.request(force=True) if self.network_sampler else None)
        box.pack_start(flow([self.network_scope, refresh], maximum=2), False, False, 0)
        self.network_model = Gtk.ListStore(*([str] * 12))
        self.network_panel = HistoryPanel(self.network_model,
            ['Protocol', 'Local endpoint', 'Remote endpoint', 'State', 'UID', 'Socket inode', 'PID(s)', 'Application(s)'], 10)
        self.network_panel.detail_formatter = self.network_details
        self.network_panel.search.set_placeholder_text('Filter current socket snapshot…')
        self.network_panel.row_filter = lambda row: (self.network_scope.get_active_id() == 'all' or
            row[8 if self.network_scope.get_active_id() == 'active' else 9] == 'yes')
        self.network_scope.connect('changed', lambda *_: self.network_panel.filtered.refilter())
        box.pack_start(self.network_panel, True, True, 0)
        return box

    def behavior_page(self):
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_border_width(16)
        content.pack_start(text_label('BEHAVIOR FLIGHT RECORDER', 'section-title'), False, False, 0)
        content.pack_start(text_label('Persistence, privilege/authentication, scan-pattern and remote-access signals from captured audit records. Medium findings include legitimate tool use and polling. These are review signals, not proof of exploitation or C2. Click a group for saved evidence and process investigation.', 'muted'), False, False, 0)
        self.behavior_scope = Gtk.ComboBoxText()
        self.behavior_scope.append('live', 'Live groups last seen within 24 hours')
        self.behavior_scope.append('all', 'All retained groups, including historical imports')
        self.behavior_scope.set_active_id('live')
        self.behavior_scope.connect('changed', lambda *_: self.refresh())
        content.pack_start(self.behavior_scope, False, False, 0)
        self.behavior_summary = text_label('Waiting for saved behavior findings…', 'muted')
        content.pack_start(self.behavior_summary, False, False, 0)
        self.behavior_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        content.pack_start(self.behavior_list, False, False, 0)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add(content)
        return scroll

    def update_behavior(self):
        stats = self.store.alert_stats()
        rows, live = behavior_groups(self.store.rows(alerts=True, limit=2000), stats, time.time())
        self.cluster.set_behavior(len(live))
        displayed = live if self.behavior_scope.get_active_id() == 'live' else rows
        self.behavior_summary.set_text(f'{len(live)} live groups last seen within 24h · {len(rows)} retained behavior groups · showing newest {min(40, len(displayed))}. Gauge counts groups, not event volume; reviewed groups remain included.')
        key = tuple((tuple(row), stats[row[0]]) for row in displayed[:40])
        if key == self.behavior_key:
            return
        self.behavior_key = key
        for child in self.behavior_list.get_children():
            self.behavior_list.remove(child)
            child.destroy()
        if not displayed:
            self.behavior_list.pack_start(text_label('No matching behavior groups in this view. Missing audit records can prevent correlation; this is not a clean-host verdict.', 'muted'), False, False, 0)
        for identity, timestamp, rule, severity, title, detail, reviewed, *_ in displayed[:40]:
            count, first, origin, latest, historical = stats[identity]
            button = Gtk.Button()
            button.get_style_context().add_class('timeline-item')
            button.add(text_label(f'{clean(title)}\n{count} matches · first {stamp(first or timestamp)} · latest {stamp(timestamp)}\n'
                f'{"HISTORICAL" if historical else "LIVE"} · {"Reviewed" if reviewed else "Needs review"} · {rule}\n'
                f'First linked event: {clean(origin)}\nLatest linked event: {clean(latest)}'))
            button.connect('clicked', lambda _, selected=identity: self.open_alert(selected))
            self.behavior_list.pack_start(button, False, False, 0)
        self.behavior_list.show_all()

    def update_network(self):
        data = self.network_snapshot
        fresh = data is not None and 0 <= time.time() - data['captured'] <= 15
        visible = fresh and data['tables'] > 0
        self.cluster.set_network(data['active'] if visible else None, not data['complete'] if data else True)
        if data is None:
            text = 'DEMO · host network inspection disabled' if self.demo else 'Network snapshot pending; visibility unknown.'
        else:
            quality = 'STALE' if not fresh else 'UNAVAILABLE' if not data['tables'] else 'PARTIAL' if not data['complete'] else 'SNAPSHOT'
            text = (f"{quality} · {data['active']} observed active sockets ({data['tcp']} TCP / {data['udp']} UDP) · "
                f"{data['listening']} listening TCP · {data['namespace'] or 'namespace unknown'} · {stamp(data['captured'])}")
            if not data['tables']:
                text = f"{quality} · active connection count unknown · {stamp(data['captured'])}"
            if data['notes']:
                text += '\n' + ' '.join(data['notes'])
            if self.network_rendered is not data:
                self.network_rows_by_key = {'|'.join((row['protocol'], row['inode'], row['local'], row['remote'])): row for row in data['rows']}
                self.network_panel.update([[row['protocol'], row['local'], row['remote'], row['state'], row['uid'], row['inode'],
                    ', '.join(owner['pid'] for owner in row.get('owners', [])) or 'Unavailable',
                    ', '.join(dict.fromkeys(owner['application'] for owner in row.get('owners', []))) or 'No visible holder',
                    'yes' if row['active'] else 'no', 'yes' if row['listening'] else 'no',
                    '|'.join((row['protocol'], row['inode'], row['local'], row['remote'])), str(data['captured'])] for row in data['rows']])
                self.network_rendered = data
        self.network_summary.set_text(text)
        self.network_status.set_text(text + '\nRefreshes about every 5s. Select a row for process-holder details. Missing holders can mean permission gaps, exited processes, inode zero or scan limits. Stale rows remain last-observed evidence.')

    def network_details(self, model_row):
        row = self.network_rows_by_key.get(model_row[10])
        if not row:
            return 'This socket is no longer in the current snapshot. Refresh and select a current row.'
        data = self.network_snapshot
        lines = [f"SOCKET SNAPSHOT\n{row['protocol']} · {row['state']}\n{row['local']} → {row['remote']}\n"
                 f"Socket UID: {row['uid']} · inode: {row['inode']}\nSnapshot: {stamp(data['captured'])}",
                 'OBSERVED PROCESS HOLDERS']
        for owner in row.get('owners', []):
            lines.append(f"PID: {owner['pid']} · application: {owner['application']}\nExecutable: {owner['exe']}\nProcess start ticks: {owner['start_ticks']}")
        if not row.get('owners'):
            lines.append('No visible holder confirmed. This does not mean the connection has no process.')
        lines.extend(data.get('owner_notes', []))
        lines.append('ASSOCIATION LIMITS\nMatched socket descriptor inodes, rechecked process start/executable and descriptor. '
            'A holder can inherit or receive a socket; it need not have initiated the connection. '
            'Process visibility is limited by ordinary-user permissions and bounded scans. '
            'Snapshots can race with exit, exec and descriptor changes. No command arguments are read or executed. '
            'The application name is the executable basename, not a verified product identity. This view performs no containment.')
        return '\n\n'.join(lines)

    def open_alert(self, identity):
        panel = self.history_panels[0]
        self.alert_scope.set_active_id("all")
        panel.search.set_text("")
        panel.filtered.refilter()
        self.pages.set_visible_child_name("alerts")
        self.alert_pin = identity
        # Behavior history can reference an older group outside the latest 500.
        if not panel.select_id(identity):
            self.refresh()
        panel.select_id(identity)

    def saved_details(self, data):
        accounts = self.local_accounts if data.get('node') in {'local', os.uname().nodename} else {}
        lines = [f"Types={clean(data.get('types'))}; result={clean(data.get('result'))}; key={clean(data.get('key'))}",
                 f"Recorded operation: {clean(data.get('operation') or 'not retained by this version')} · syscall return: {clean(data.get('exit') or 'not recorded')}",
                 f"Executable: {clean(data.get('exe'))}\nOriginating login: {clean(user_label(data.get('auid', ''), accounts))}\n"
                 f"Real UID: {clean(user_label(data.get('uid', ''), accounts))} · effective UID: {clean(user_label(data.get('euid', ''), accounts))}\n"
                 f"PID={clean(data.get('pid'))}; parent PID={clean(data.get('ppid'))}; session={clean(data.get('session'))}; host={clean(data.get('node'))}"]
        if data.get('unit'):
            lines.append(f"Recorded service unit: {clean(data['unit'])}; audit metadata, not independently verified service attribution.")
        for target in data.get('targets', [])[:8]:
            lines.append(f"Captured path: {clean(target.get('path'))} · PATH role: {clean(target.get('kind'))}; lexical path, contents not inspected.")
        for connection in data.get('connections', [])[:32]:
            lines.append(f"Recorded connect destination: [{clean(connection.get('ip'))}]:{clean(connection.get('port'))} · result={clean(data.get('result'))}; historical syscall evidence, not a current socket.")
        for item in data.get('persistence', [])[:8]:
            lines.append(f"Persistence location: {clean(item.get('target'))}\nMechanism: {clean(item.get('rule'))} · operation: {clean(item.get('operation'))} · file contents not inspected")
        if data.get('exe') == '/usr/bin/sbctl' and any(item.get('path', '').endswith('.efi') for item in data.get('targets', [])[:8]):
            lines.append('POSSIBLE MAINTENANCE CONTEXT: sbctl can sign EFI files during boot/update/snapshot maintenance. '
                         'The executable/path pair alone does not verify the trigger, signature, file integrity or authorization.')
        return '\n\n'.join(lines)

    def event_details(self, row):
        saved = self.store.db.execute('SELECT data FROM events WHERE id=?', (row[9],)).fetchone()
        return (f'SAVED AUDIT EVIDENCE\n{clean(row[9])}\n\n' + self.saved_details(json.loads(saved[0]))
                if saved else 'This event summary is no longer retained.')

    def alert_details(self, row):
        why, next_steps = guidance(row[3])
        events, limits = self.store.investigation(row[0])
        lines = [f"WHAT HAPPENED\n{row[4]}", f"WHY THIS RULE MATCHED\n{why}",
                 f"LATEST EVIDENCE\n{row[5]}",
                 f"GROUP\n{row[8]} occurrences · first seen {row[9]} · last seen {row[1]}",
                 f"WHAT TO CHECK\n{next_steps}", f"RELATED SAVED EVENTS\n{limits}"]
        for identity, timestamp, data in events:
            lines.append(f"{stamp(timestamp)} · {clean(identity)}\n" + self.saved_details(data))
        nearby, nearby_limits = self.store.nearby_context(row[0])
        lines.append('NEARBY HOST ACTIVITY — MAY BE UNRELATED\n' + nearby_limits)
        for identity, timestamp, data in nearby:
            lines.append(f"{stamp(timestamp)} · {clean(identity)}\n" + self.saved_details(data))
        lines.append("INVESTIGATE / CONTAIN\nUse ‘Inspect process & connections’ for a current read-only snapshot, exact saved-event pivots and containment suggestions.")
        lines.append("LIMITS\nSaved summaries only, not raw command arguments or a complete process tree. "
                     "History is bounded to seven days / 5,000 events / 2,000 alert groups. Missing records, "
                     "PID reuse and collection gaps can limit conclusions. No action here executes evidence or changes system rules.")
        return "\n\n".join(lines)

    def inspect_selected(self, *_):
        model, selected = self.alert_view.get_selection().get_selected()
        if selected is None:
            self.message("Select an alert first, then inspect its saved event and current process context.")
            return
        row = list(model[selected])
        stats = self.store.alert_stats().get(row[0])
        last_id = stats[3] if stats else ''
        saved = self.store.db.execute("SELECT id,ts,data FROM events WHERE id=?", (last_id,)).fetchone()
        dialog = Gtk.Window(title=f"Skidplate · investigate alert {row[0]}", transient_for=self.window)
        dialog.set_default_size(980, 720)
        dialog.get_style_context().add_class("skidplate")
        state = {'closed': False, 'anchor': saved}
        dialog.connect('destroy', lambda *_: state.update(closed=True))
        layout = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        layout.set_border_width(20)
        dialog.add(layout)
        layout.pack_start(text_label(clean(row[4]), 'section-title'), False, False, 0)
        layout.pack_start(text_label('Saved evidence → process → sockets → related events → containment review', 'muted'), False, False, 0)
        tabs = Gtk.Notebook()
        layout.pack_start(tabs, True, True, 0)

        def text_page(title, text):
            view = Gtk.TextView(editable=False, cursor_visible=True)
            view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            view.set_left_margin(20); view.set_right_margin(20)
            view.set_top_margin(16); view.set_bottom_margin(16)
            set_evidence(view.get_buffer(), text)
            scroll = Gtk.ScrolledWindow()
            scroll.add(view)
            tabs.append_page(scroll, Gtk.Label(label=title))
            return view

        text_page('Evidence', self.alert_details(row))
        live = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        live.set_border_width(16)
        status = text_label('Choose Refresh snapshot. Current process/socket data is separate from the recorded event.', 'muted')
        status.set_selectable(True)
        status_scroll = Gtk.ScrolledWindow()
        status_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        status_scroll.set_size_request(-1, 150)
        status_scroll.add(status)
        live.pack_start(status_scroll, False, False, 0)
        refresh = Gtk.Button(label='Refresh process & socket snapshot')
        refresh.set_sensitive(not self.demo)
        live.pack_start(refresh, False, False, 0)
        sockets = Gtk.ListStore(*([str] * 6))
        socket_panel = HistoryPanel(sockets, ['Protocol', 'Local endpoint', 'Remote endpoint', 'State', 'Socket inode', 'PID'], 4)
        live.pack_start(socket_panel, True, True, 0)
        tabs.append_page(live, Gtk.Label(label='Process & sockets'))

        def completed(result):
            self.inspection_busy = False
            if state['closed']:
                return False
            refresh.set_sensitive(not self.demo)
            process = result.get('process', {})
            anchor = state['anchor']
            lines = ([f"Saved event: {clean(anchor[0])} · {stamp(anchor[1])}"] if anchor else []) + [result['status']]
            if process:
                lines.append(f"PID {process['pid']} · parent {process['ppid']} · UID {process['uid']} · eUID {process['euid']} · state {process['state']}\nExecutable: {process['exe']}\nStarted: {stamp(process['start'])} · Snapshot: {stamp(time.time())}")
            lines.extend(result.get('notes', []))
            lines.append('No listed socket is not proof of no network activity. Permissions, namespaces, short-lived sockets and scan limits restrict visibility. Shared/inherited sockets are possible.')
            status.set_text('\n\n'.join(lines))
            socket_panel.update([[c['protocol'], c['local'], c['remote'], c['state'], c['inode'], process.get('pid', '')]
                                 for c in result.get('connections', [])])
            return False

        def inspect_now(*_):
            if self.demo:
                status.set_text('Demo events cannot be associated with host processes.')
                return
            if self.inspection_busy:
                status.set_text('Another process inspection is still running; retry shortly.')
                return
            anchor = state['anchor']
            if not anchor:
                status.set_text('The linked event has expired or was not saved. Use Related events to select another saved record.')
                return
            summary, timestamp = json.loads(anchor[2]), anchor[1]
            self.inspection_busy = True
            refresh.set_sensitive(False)
            socket_panel.update([])
            status.set_text('Reading current process metadata and matching owned socket inodes…')
            def worker():
                try:
                    result = snapshot(summary, timestamp)
                except Exception:
                    result = {'status': 'Process inspection failed; no live association confirmed.', 'connections': []}
                GLib.idle_add(completed, result)
            threading.Thread(target=worker, daemon=True, name='skidplate-inspect').start()
        refresh.connect('clicked', inspect_now)

        related = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        related.set_border_width(16)
        related.pack_start(text_label('Exact matches across all retained events (up to 200 results). PID, user or executable matches are pivots, not proof of causation or the same process lifetime.', 'muted'), False, False, 0)
        field = Gtk.ComboBoxText()
        for name in ('pid', 'ppid', 'exe', 'auid', 'session', 'node'):
            field.append(name, {'pid': 'PID', 'ppid': 'Parent PID', 'exe': 'Executable', 'auid': 'Login UID', 'session': 'Audit session', 'node': 'Host'}[name])
        value = Gtk.Entry()
        search = Gtk.Button(label='Find related events')
        related.pack_start(flow([field, value, search], maximum=3), False, False, 0)
        related_model = Gtk.ListStore(*([str] * 7))
        related_panel = HistoryPanel(related_model, ['Event ID', 'Time', 'PID', 'Parent PID', 'Executable', 'Login UID', 'Session'], 0)
        related.pack_start(related_panel, True, True, 0)
        def choose_field(*_):
            anchor = state['anchor']
            value.set_text(json.loads(anchor[2]).get(field.get_active_id(), '') if anchor else '')
        field.connect('changed', choose_field)
        field.set_active_id('pid')
        def find_related(*_):
            related_panel.update([[identity, stamp(ts), data.get('pid', ''), data.get('ppid', ''), data.get('exe', ''), data.get('auid', ''), data.get('session', '')]
                for identity, ts, data in self.store.related(field.get_active_id(), value.get_text())])
        search.connect('clicked', find_related)
        select_event = Gtk.Button(label='Use selected event for process lookup')
        def use_event(*_):
            identity = related_panel.selected_id()
            if not identity or self.inspection_busy:
                return
            state['anchor'] = self.store.db.execute('SELECT id,ts,data FROM events WHERE id=?', (identity,)).fetchone()
            socket_panel.update([])
            status.set_text('Saved event changed. Refresh to inspect its current process; previous snapshot cleared.')
            tabs.set_current_page(1)
        select_event.connect('clicked', use_event)
        related.pack_start(select_event, False, False, 0)
        tabs.append_page(related, Gtk.Label(label='Related events'))
        text_page('Containment review', containment_guidance(row[3]))
        close = Gtk.Button(label='Close investigation')
        close.connect('clicked', lambda *_: dialog.destroy())
        layout.pack_end(close, False, False, 0)
        dialog.show_all()
        find_related()
        tabs.set_current_page(1)
        inspect_now()

    def update_overview(self, alerts, unread, high, available, dns_ok, quiet):
        self.cluster.update(int(self.store.get('events_processed', '0')), high,
                            len(RULES) - len(self.engine.muted), len(RULES), available, quiet)
        state = "Log access lost" if self.follower.access_lost else "Readable" if available else "Unavailable"
        self.instruments["Monitoring"].update(state,
            "Audit input only; daemon health and rule coverage unverified.", "ok" if available and not quiet else "warning")
        self.instruments["Important signals"].update(high, f"{unread} total unreviewed alert groups; all findings remain available.", "danger" if high else "info")
        self.instruments["Behavior rules"].update("Audit correlations", "Persistence, privilege/authentication, scan-pattern and remote-access signals. Collection coverage remains unverified.")
        self.instruments["Noise control"].update("Grouped", "Matching alerts share a row for one hour; every retained event remains searchable.")
        self.protection["Host"].update("Audit rules", f"{len(RULES)-len(self.engine.muted)}/{len(RULES)} detection rules enabled")
        self.protection["Network"].update("Connections", "Supported audit connect records only; no packet IDS.")
        self.protection["Correlation"].update("Local context", "Strict process/session matching when audit metadata is available.")
        self.protection["DNSSEC"].update("Reader ready" if dns_ok else "Off / unavailable",
            "Validation mode and DNS coverage remain unverified.", "info" if dns_ok else "warning")
        self.overview_health.set_text(self.follower.status + "\n" +
            (self.resolver.status if self.resolver else "DNSSEC telemetry disabled") +
            f"\nSource: {clean(self.follower.path)} · Rotations: {self.follower.rotations} · Last audit event: {stamp(self.last_event) if self.last_event else 'none'}")
        key = tuple(tuple(row[:7]) for row in alerts[:12])
        priority = [row for row in alerts if row[3] == "high" and row[2] in IMPORTANT_RULES and not row[6]][:5]
        key = (key, tuple(row[0] for row in priority))
        if self.timeline_key == key:
            return
        self.timeline_key = key
        for box, rows in ((self.priority, priority), (self.timeline, alerts[:8])):
            for child in box.get_children():
                box.remove(child)
                child.destroy()
            if not rows:
                box.pack_start(text_label("No matching alerts in the latest 500 displayed rows. This is not a clean-host verdict.", "muted"), False, False, 0)
            for identity, timestamp, rule, severity, title, detail, *_ in rows:
                button = Gtk.Button()
                button.get_style_context().add_class("timeline-item")
                button.get_style_context().add_class(severity)
                button.add(text_label(f"{stamp(timestamp)}  ·  {severity.upper()}  ·  {rule}\n{clean(title)}"))
                button.connect("clicked", lambda _, selected=identity: self.open_alert(selected))
                box.pack_start(button, False, False, 0)
            box.show_all()

    def controls(self, source):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(20)
        for text in ["Only events captured by your existing audit rules can be detected.",
                     "Skidplate runs as your account. The optional authenticated helper only grants read access to existing audit logs; it does not change audit rules.",
                     "Stored locally: up to 5,000 event summaries and 2,000 alerts, for 7 days. Raw records and command arguments are not stored.",
                     "Recent history is analyzed into Alerts without desktop notifications or root-baseline training."]:
            label = Gtk.Label(label=text, xalign=0)
            label.set_line_wrap(True)
            box.pack_start(label, False, False, 0)
        source_row = Gtk.Box(spacing=6)
        self.source_entry = Gtk.Entry(text=str(source))
        source_row.pack_start(self.source_entry, True, True, 0)
        switch = Gtk.Button(label="Read this log")
        switch.connect("clicked", self.switch_source)
        source_row.pack_start(switch, False, False, 0)
        box.pack_start(source_row, False, False, 0)
        self.access_button = Gtk.Button(label="Enable audit log reading…")
        self.access_button.set_sensitive(not self.demo)
        self.access_button.connect("clicked", self.enable_log_reading)
        box.pack_start(self.access_button, False, False, 0)
        self.access_status = text_label("No permission request has been made.", "muted")
        box.pack_start(self.access_status, False, False, 0)
        box.pack_start(text_label("Administrator authentication required. Applies only to /var/log/audit/audit.log and numbered rotations, for your existing account. Rotation or reboot may require enabling access again.", "muted"), False, False, 0)
        notify = Gtk.CheckButton(label="Desktop notifications (generic titles; details stay in the dashboard)")
        notify.set_active(self.notifications)
        notify.connect("toggled", self.set_notifications)
        box.pack_start(notify, False, False, 0)
        high_only = Gtk.CheckButton(label="Only High-severity alert popups (all severities stay in history)")
        high_only.set_active(self.high_only)
        high_only.connect("toggled", self.set_high_only)
        box.pack_start(high_only, False, False, 0)
        focused = Gtk.CheckButton(label="Focused popups: behavior chains and direct high-risk signals (other findings stay in All alerts)")
        focused.set_active(self.focused_popups)
        focused.connect("toggled", lambda widget: self.set_focused_popups(widget.get_active()))
        box.pack_start(focused, False, False, 0)
        dns = Gtk.CheckButton(label="Read systemd-resolved DNSSEC security events (normal-user journal access required)")
        dns.set_active(self.resolver is not None)
        dns.set_sensitive(not self.demo)
        dns.connect("toggled", self.set_dns_telemetry)
        box.pack_start(dns, False, False, 0)
        network_label = Gtk.Label(label="Destination watchlist: IPs/CIDRs separated by spaces. Empty means no destination matches. Requires connect/SOCKADDR audit coverage; does not block traffic.", xalign=0)
        network_label.set_line_wrap(True)
        box.pack_start(network_label, False, False, 0)
        network_row = Gtk.Box(spacing=8)
        self.network_entry = Gtk.Entry(text=self.store.get("network_watchlist"))
        self.network_entry.set_placeholder_text("For example: 192.0.2.10 2001:db8::/32")
        network_row.pack_start(self.network_entry, True, True, 0)
        save_network = Gtk.Button(label="Save destination watchlist")
        save_network.connect("clicked", self.save_network_watchlist)
        network_row.pack_start(save_network, False, False, 0)
        box.pack_start(network_row, False, False, 0)
        for rule, description in RULES.items():
            toggle = Gtk.CheckButton(label=f"{rule}: {description}")
            toggle.set_active(rule not in self.engine.muted)
            toggle.connect("toggled", self.toggle_rule, rule)
            box.pack_start(toggle, False, False, 0)
        line = Gtk.Box(spacing=8)
        line.pack_start(Gtk.Label(label="Authentication threshold:"), False, False, 0)
        threshold = Gtk.SpinButton.new_with_range(3, 30, 1)
        threshold.set_value(self.engine.auth_threshold)
        line.pack_start(threshold, False, False, 0)
        line.pack_start(Gtk.Label(label="events in seconds:"), False, False, 0)
        window = Gtk.SpinButton.new_with_range(60, 3600, 30)
        window.set_value(self.engine.auth_window)
        line.pack_start(window, False, False, 0)
        apply = Gtk.Button(label="Apply threshold")
        def apply_threshold(_):
            self.engine.auth_threshold, self.engine.auth_window = threshold.get_value_as_int(), window.get_value_as_int()
            self.engine.failures.clear()
            self.store.set("auth_threshold", self.engine.auth_threshold)
            self.store.set("auth_window", self.engine.auth_window)
        apply.connect("clicked", apply_threshold)
        line.pack_start(apply, False, False, 0)
        box.pack_start(line, False, False, 0)
        learn = Gtk.Button(label="Learn root executables for another 24h")
        learn.connect("clicked", lambda _: self.set_learning(time.time() + 86400))
        arm = Gtk.Button(label="Finish learning now")
        arm.connect("clicked", lambda _: self.set_learning(time.time() - 1))
        baseline = flow([learn, arm], maximum=2)
        box.pack_start(baseline, False, False, 0)
        label = Gtk.Label(label="Learning observes executables, not intent. Only train on a system you trust. Disabled rules do not create alerts; matching events remain in Events.", xalign=0)
        label.set_line_wrap(True)
        box.pack_start(label, False, False, 0)
        def wrap_labels(widget):
            if isinstance(widget, Gtk.Label):
                widget.set_line_wrap(True)
                widget.set_line_wrap_mode(2)
                widget.set_max_width_chars(64)
            elif isinstance(widget, Gtk.Container):
                for child in widget.get_children():
                    wrap_labels(child)
        wrap_labels(box)
        scroll = Gtk.ScrolledWindow()
        scroll.add(box)
        return scroll

    def set_learning(self, until):
        self.engine.learning_until = until
        self.store.set("learning_until", until)
        self.refresh()

    def set_notifications(self, toggle):
        self.notifications = toggle.get_active()
        self.store.set("notifications", int(self.notifications))

    def set_high_only(self, toggle):
        self.high_only = toggle.get_active()
        self.store.set("high_only", int(self.high_only))
        self.refresh()

    def set_focused_popups(self, enabled):
        self.focused_popups = enabled
        self.store.set("focused_popups", int(enabled))
        self.refresh()

    def set_dns_telemetry(self, toggle):
        enabled = toggle.get_active() and not self.demo
        if self.resolver:
            self.resolver.close()
        self.resolver = ResolverFollower() if enabled else None
        self.resolver_notified = False
        self.store.set("dns_telemetry", int(enabled))
        self.refresh()

    def save_network_watchlist(self, _):
        try:
            networks = network_watchlist(self.network_entry.get_text())
        except ValueError:
            self.message("Enter at most 64 valid destination IPs/CIDRs, separated by spaces or commas.")
            return
        text = " ".join(str(network) for network in networks)
        self.store.set("network_watchlist", text)
        self.engine.watched_networks = networks
        self.network_entry.set_text(text)

    def message(self, text):
        dialog = Gtk.MessageDialog(transient_for=self.window, modal=True,
            message_type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK, text=text)
        dialog.run()
        dialog.destroy()

    def snooze_selected(self, _):
        model, row = self.alert_view.get_selection().get_selected()
        if row is None:
            self.message("Select an alert first. Snoozing stops matching popups while keeping evidence in history.")
            return
        try:
            self.store.snooze_alert(model[row][0], (600, 3600, 86400)[self.snooze_duration.get_active()])
        except ValueError as exc:
            self.message(str(exc))
            return
        self.refresh()

    def clear_event_snoozes(self, _):
        self.store.clear_snoozes()
        self.refresh()

    def toggle_rule(self, toggle, rule):
        if toggle.get_active():
            self.engine.muted.discard(rule)
        else:
            self.engine.muted.add(rule)
        self.store.set("muted_rules", ",".join(sorted(self.engine.muted)))

    def switch_source(self, _):
        candidate = Path(self.source_entry.get_text()).expanduser()
        if not candidate.is_absolute():
            self.health.set_text("Use an absolute path to a readable audit log.")
            return
        self.follower.close()
        self.follower = LogFollower(candidate)
        self.assembler = Assembler()
        self.engine.reset_correlation()
        self.started = time.time()
        self.last_event = None
        self.last_live_received = None
        self.quiet_notified = False
        self.parse_skipped = 0
        self.skip_notified = False
        self.unavailable_notified = False

    def acknowledge(self, _):
        model, row = self.alert_view.get_selection().get_selected()
        if row is None:
            self.message("Select an alert to mark reviewed. Other alerts will remain unreviewed.")
            return
        self.store.db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (model[row][0],))
        self.store.db.commit()
        self.refresh()

    def notify(self, title, severe=False):
        now = time.time()
        if not self.notifications or now < self.snoozed_until:
            return
        while self.notice_times and self.notice_times[0] < now - 60:
            self.notice_times.popleft()
        if len(self.notice_times) >= 6:
            return
        self.notice_times.append(now)
        notice = Notify.Notification.new(("DEMO · " if self.demo else "") + clean(title, 120),
            "Open Skidplate for local evidence and monitoring status.", "security-high-symbolic")
        notice.set_urgency(Notify.Urgency.CRITICAL if severe else Notify.Urgency.NORMAL)
        try:
            notice.show()
        except GLib.Error:
            pass

    def tick(self):
        if self.network_sampler:
            result = self.network_sampler.poll()
            if result is not None:
                self.network_snapshot = result
            self.network_sampler.request()
        self.update_network()
        try:
            for line in self.follower.poll():
                try:
                    record = parse_line(line)
                except ValueError:
                    self.parse_skipped += 1
                    continue
                if record:
                    for event in self.assembler.feed(record):
                        self.consume(event)
                elif line.strip():
                    self.parse_skipped += 1
            for event in self.assembler.flush():
                self.consume(event)
            if self.resolver:
                for record in self.resolver.poll():
                    self.consume(Event([record]), audit_source=False)
                self.resolver.acknowledge()
                unavailable = self.resolver.status.startswith("DNSSEC telemetry unavailable")
                if unavailable and not self.resolver_notified:
                    self.notify("DNS security telemetry unavailable")
                self.resolver_notified = unavailable
            if self.parse_skipped + self.follower.skipped + self.assembler.dropped and not self.skip_notified:
                self.notify("Some audit data could not be fully analyzed")
                self.skip_notified = True
            if self.follower.status.startswith("MONITORING UNAVAILABLE"):
                if not self.unavailable_notified:
                    self.notify("Log access lost" if self.follower.access_lost else "Audit monitoring unavailable", severe=True)
                    self.unavailable_notified = True
            else:
                self.unavailable_notified = False
                if time.time() - (self.last_live_received or self.started) > 900 and not self.quiet_notified:
                    self.notify("No recent audit events · check coverage")
                    self.quiet_notified = True
            if time.monotonic() >= self.refresh_at:
                self.monitor_error = ""
                self.store.retain()
                self.refresh()
                self.refresh_at = time.monotonic() + 2
        except (OSError, ValueError, sqlite3.Error) as exc:
            if self.resolver:
                self.resolver.retry_pending()
            self.store.db.rollback()
            self.engine.reset_correlation()
            self.monitor_error = f"MONITORING ERROR · {clean(exc)}"
            self.health.set_text(self.monitor_error)
            self.indicator.set_icon_full(str(ROOT / "assets/shield-warning.svg"), "Monitoring error")
            self.menu_status.set_label("Monitoring error · open dashboard")
        return True

    def consume(self, event, audit_source=True):
        if audit_source:
            self.last_event = max(self.last_event or 0, event.timestamp)
        historical = not self.demo and event.timestamp < self.started
        if audit_source and not historical and -60 <= time.time() - event.timestamp <= 600:
            self.last_live_received = time.time()
            self.quiet_notified = False
        for alert in self.engine.process(event, historical=historical):
            if (not historical and alert.wants_notification(self.high_only) and
                    (not self.focused_popups or alert.rule in IMPORTANT_RULES)):
                self.notify(alert.title, severe=alert.severity == "high")

    def refresh(self):
        events, alerts = self.store.rows(), self.store.rows(alerts=True)
        if self.alert_pin is not None and not any(row[0] == self.alert_pin for row in alerts):
            pinned = self.store.db.execute('SELECT id,ts,rule,severity,title,detail,acknowledged,fingerprint '
                                          'FROM alerts WHERE id=?', (self.alert_pin,)).fetchone()
            if pinned:
                alerts = alerts[:499] + [pinned]
        event_rows, alert_rows = [], []
        for identity, timestamp, data in events:
            values = json.loads(data)
            event_rows.append([stamp(timestamp), values["types"], values["auid"], values["uid"],
                values["account"], values["address"], values["exe"], values["result"], values["key"], clean(identity),
                values.get("pid", ""), values.get("ppid", ""), values.get("euid", ""),
                values.get("session", ""), values.get("node", "")])
        snoozes = self.store.active_snoozes()
        stats = self.store.alert_stats()
        for identity, timestamp, rule, severity, title, detail, ack, fingerprint in alerts:
            status = ("Matching snooze until " + stamp(snoozes[fingerprint]) if fingerprint in snoozes else
                      "Historical; no popup" if detail.startswith("Historical finding;") else
                      "Notifications off" if not self.notifications else
                      "Focused mode; saved quietly" if self.focused_popups and rule not in IMPORTANT_RULES else
                      "High-only; saved quietly" if self.high_only and severity != "high" else "Eligible for popups")
            occurrences, first_seen, _, _, _ = stats[identity]
            alert_rows.append([identity, stamp(timestamp), severity.upper(), rule, title, detail,
                                     "Yes" if ack else "No", status, occurrences, stamp(first_seen or timestamp), fingerprint])
        self.history_panels[0].update(alert_rows)
        self.history_panels[1].update(event_rows)
        unread = self.store.db.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
        high = sum(rule in IMPORTANT_RULES for (rule,) in self.store.db.execute(
            "SELECT rule FROM alerts WHERE acknowledged=0 AND severity='high'"))
        skipped = self.parse_skipped + self.follower.skipped + self.assembler.dropped
        available = not self.monitor_error and not self.follower.status.startswith(("MONITORING UNAVAILABLE", "Not connected"))
        quiet = time.time() - (self.last_live_received or self.started) > 900
        self.health.set_text(("DEMO DATA · " if self.demo else "") +
            (self.monitor_error or self.follower.status) +
            ("\nNo recent live audit events; check coverage." if quiet and available else ""))
        learning = ("Waiting for first live root exec to start learning" if self.engine.learning_until == 0 else
                    "Learning root baseline until " + stamp(self.engine.learning_until) if time.time() < self.engine.learning_until else "Root baseline armed")
        self.stats.set_text(f"{unread} unreviewed alert groups · {len(events)} recent events shown (max 500) · {len(RULES)-len(self.engine.muted)}/{len(RULES)} rules enabled · {len(snoozes)} event snoozes · {learning}")
        dns_ok = self.resolver is not None and self.resolver.status.startswith("DNSSEC journal read succeeded")
        icon = "shield-alert.svg" if high else "shield.svg" if available and dns_ok and not skipped and not quiet and not self.engine.muted else "shield-warning.svg"
        self.indicator.set_icon_full(str(ROOT / "assets" / icon), "Skidplate monitoring status")
        self.menu_status.set_label(("DEMO · " if self.demo else "") +
            ("Log access lost" if self.follower.access_lost else "Source readable" if available else "Monitoring unavailable") +
            (" · DNSSEC reader ready" if dns_ok else " · DNSSEC reader off/unavailable") + f" · {unread} alerts")
        self.update_overview(alerts, unread, high, available, dns_ok, quiet)
        self.update_behavior()
        self.update_network()

    def show(self, *_):
        self.window.show_all()
        self.window.present()

    def hide(self, *_):
        self.save_layout()
        self.window.hide()
        return True

    def snooze(self, *_):
        self.snoozed_until = time.time() + 600

    def enable_log_reading(self, *_):
        if self.demo or self.access_request is not None:
            return
        dialog = Gtk.MessageDialog(transient_for=self.window, modal=True,
            message_type=Gtk.MessageType.QUESTION, buttons=Gtk.ButtonsType.OK_CANCEL,
            text="Allow your account to read existing audit logs?")
        dialog.format_secondary_text("An administrator must authenticate. Every application running as your account will be able to read these logs. No new group is created. This grants read access to existing audit.log files only; access may need renewal after rotation or reboot.")
        response = dialog.run()
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return
        self.access_request = Gio.Cancellable()
        self.access_button.set_sensitive(False)
        self.access_status.set_text("Waiting for administrator authentication…")
        def finished(message):
            self.access_request = None
            self.access_button.set_sensitive(True)
            self.access_status.set_text(message)
        def replied(bus, result, *_):
            try:
                number = bus.call_finish(result).unpack()[0]
                finished(f"Read access enabled for {number} existing audit logs. Monitoring will retry automatically.")
            except GLib.Error:
                finished("Log access was not confirmed. Authentication may have been cancelled or the helper is not installed. See docs/log-access.md. Some grants may have applied.")
        def connected(_source, result, *_):
            try:
                bus = Gio.bus_get_finish(result)
                bus.call('org.skidplate.LogAccess1', '/org/skidplate/LogAccess1',
                    'org.skidplate.LogAccess1', 'EnableRead', None,
                    GLib.VariantType.new('(u)'), Gio.DBusCallFlags.NONE,
                    130000, self.access_request, replied)
            except GLib.Error:
                finished("System bus unavailable. Log access was not changed by this request.")
        Gio.bus_get(Gio.BusType.SYSTEM, self.access_request, connected)

    def quit(self, *_):
        if self.network_sampler:
            self.network_sampler.close()
        if self.access_request is not None:
            self.access_request.cancel()
        self.save_layout()
        if self.resolver:
            self.resolver.close()
        self.follower.close()
        self.store.db.close()
        os.close(self.lockfd)
        Gtk.main_quit()

    def save_layout(self):
        try:
            width, height = self.window.get_size()
            self.store.set("window_width", min(2400, max(480, width)))
            self.store.set("window_height", min(1800, max(400, height)))
            for index, panel in enumerate(self.history_panels):
                self.store.set(f"detail_split_{index}", round(panel.fraction * 100))
        except sqlite3.Error:
            # A layout preference must never prevent hiding/exiting the app.
            self.store.db.rollback()


def main():
    parser = argparse.ArgumentParser(prog="skidplate", description="Skidplate local audit-log tray monitor; never run as root")
    parser.add_argument('--version', action='version', version='Skidplate ' + __version__)
    parser.add_argument("--source", type=Path, default=Path("/var/log/audit/audit.log"))
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--background", action="store_true")
    parser.add_argument("--demo", action="store_true", help="Synthetic events with disposable state; no host logs")
    options = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Run the desktop interface as your normal user, never with sudo")
    if not Gtk.init_check()[0]:
        parser.exit(2, "No graphical display available. Start from your desktop terminal.\n")
    if options.demo:
        with tempfile.TemporaryDirectory(prefix="skidplate-demo-") as directory:
            base = Path(directory)
            source = base / "demo.log"
            from .demo import sample
            source.write_text(sample(time.time()))
            Dashboard(source, base / "state", demo=True, background=options.background)
            Gtk.main()
    else:
        state_home = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
        if not state_home.is_absolute():
            parser.error("XDG_STATE_HOME must be absolute")
        state = options.state_dir or default_state(state_home)
        Dashboard(options.source.expanduser().absolute(), state.expanduser().absolute(), background=options.background)
        Gtk.main()


if __name__ == "__main__":
    main()
