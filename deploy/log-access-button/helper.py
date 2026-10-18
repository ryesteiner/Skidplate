"""Fixed-purpose system-bus service. Install root-owned; never run this source as root.

Authoritative interfaces: libacl headers, D-Bus specification and Polkit Authority.
No client paths, usernames, commands, or log contents are accepted.
"""
import ctypes
import os
import pwd
import re
import stat
from contextlib import ExitStack

BUS = 'org.skidplate.LogAccess1'
OBJECT = '/org/skidplate/LogAccess1'
ACTION = 'org.skidplate.logaccess.enable'
XML = '''<node><interface name="org.skidplate.LogAccess1">
<method name="EnableRead"><arg type="u" direction="out"/></method>
</interface></node>'''
MAX_LOGS = 128


def updated_acl(text, uid, requested):
    """Preserve unrelated effective permissions when widening the ACL mask."""
    entries = {}
    for line in text.strip().splitlines():
        match = re.fullmatch(r'(user|group|mask|other):([0-9]*):([r-][w-][x-])', line)
        if not match:
            raise ValueError('Unexpected ACL')
        kind, qualifier, perms = match.groups()
        key = (kind, qualifier)
        if key in entries or (qualifier and kind not in ('user', 'group')):
            raise ValueError('Unexpected ACL entry')
        entries[key] = sum(bit for char, bit in zip(perms, (4, 2, 1)) if char != '-')
    if not all((kind, '') in entries for kind in ('user', 'group', 'other')):
        raise ValueError('Incomplete ACL')
    mask = entries.pop(('mask', ''), 7)
    for key in entries:
        if key[0] == 'group' or (key[0] == 'user' and key[1]):
            entries[key] &= mask
    target = ('user', str(uid))
    entries[target] = entries.get(target, 0) | requested
    entries['mask', ''] = 0
    for (kind, qualifier), permissions in list(entries.items()):
        if kind == 'group' or (kind == 'user' and qualifier):
            entries['mask', ''] |= permissions
    def order(item):
        kind, qualifier = item[0]
        return ({'user': 0, 'group': 1, 'mask': 2, 'other': 3}[kind],
                int(qualifier) + 1 if qualifier else 0)
    return '\n'.join(f'{kind}:{qualifier}:' + ''.join(
        char if permissions & bit else '-' for char, bit in zip('rwx', (4, 2, 1)))
        for (kind, qualifier), permissions in sorted(entries.items(), key=order)) + '\n'


class ACL:
    def __init__(self):
        self.lib = ctypes.CDLL('/usr/lib/libacl.so.1', use_errno=True)
        for name, args, result in (
            ('acl_get_fd', [ctypes.c_int], ctypes.c_void_p),
            ('acl_to_any_text', [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char, ctypes.c_int], ctypes.c_void_p),
            ('acl_from_text', [ctypes.c_char_p], ctypes.c_void_p),
            ('acl_valid', [ctypes.c_void_p], ctypes.c_int),
            ('acl_set_fd', [ctypes.c_int, ctypes.c_void_p], ctypes.c_int),
            ('acl_free', [ctypes.c_void_p], ctypes.c_int),
        ):
            function = getattr(self.lib, name)
            function.argtypes, function.restype = args, result

    @staticmethod
    def checked(value, pointer=False):
        if (pointer and not value) or (not pointer and value < 0):
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return value

    def grant(self, fd, uid, permission):
        original = self.checked(self.lib.acl_get_fd(fd), True)
        rendered = replacement = None
        try:
            rendered = self.checked(self.lib.acl_to_any_text(original, None, b'\n', 0x08), True)
            text = ctypes.string_at(rendered)
            if len(text) > 65536:
                raise ValueError('ACL too large')
            updated = updated_acl(text.decode('ascii'), uid, permission).encode('ascii')
            replacement = self.checked(self.lib.acl_from_text(updated), True)
            self.checked(self.lib.acl_valid(replacement))
            self.checked(self.lib.acl_set_fd(fd, replacement))
        finally:
            for pointer in (replacement, rendered, original):
                if pointer:
                    self.lib.acl_free(pointer)


def safe_metadata(fd, directory):
    info = os.fstat(fd)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError('Unsafe audit object')
    if not directory and info.st_nlink != 1:
        raise PermissionError('Hard-linked log rejected')


def grant_logs(uid):
    """Pin each trusted directory/file by descriptor, then update access ACLs only."""
    if uid < 1000 or uid == 65534:
        raise PermissionError('An ordinary local account is required')
    pwd.getpwuid(uid)
    with ExitStack() as stack:
        def opened(path, flags, parent=None):
            fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, fd)
            return fd
        flags = os.O_RDONLY | os.O_DIRECTORY
        directory = opened('/', flags)
        safe_metadata(directory, True)
        for component in ('var', 'log', 'audit'):
            directory = opened(component, flags, directory)
            safe_metadata(directory, True)
        files = []
        current = False
        with os.scandir(directory) as entries:
            for count, entry in enumerate(entries):
                if count >= 4096:
                    raise ValueError('Audit directory has too many entries')
                if not re.fullmatch(r'audit\.log(?:\.[1-9][0-9]{0,5})?', entry.name):
                    continue
                if len(files) >= MAX_LOGS:
                    raise ValueError('Too many rotated logs')
                fd = opened(entry.name, os.O_RDONLY | os.O_NONBLOCK, directory)
                safe_metadata(fd, False)
                files.append(fd)
                current |= entry.name == 'audit.log'
        if not current:
            raise FileNotFoundError('Current audit log missing')
        acl = ACL()
        for fd in files:
            acl.grant(fd, uid, 4)
        # Traversal only: users cannot list or write the directory.
        acl.grant(directory, uid, 1)
        return len(files)


def main():
    if os.getuid() != 0:
        raise SystemExit('This service requires the installed system D-Bus activation configuration.')
    import gi
    from gi.repository import Gio, GLib
    loop = GLib.MainLoop()
    pending = False
    connection = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

    def caller_uid(sender):
        reply = connection.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus',
            'org.freedesktop.DBus', 'GetConnectionUnixUser', GLib.Variant('(s)', (sender,)),
            GLib.VariantType.new('(u)'), Gio.DBusCallFlags.NONE, 3000, None)
        uid = reply.unpack()[0]
        if uid < 1000 or uid == 65534:
            raise PermissionError('Ordinary local account required')
        pwd.getpwuid(uid)
        return uid

    def method(bus, sender, path, interface, name, parameters, invocation):
        nonlocal pending
        if pending:
            invocation.return_dbus_error(BUS + '.Busy', 'Another authorization request is pending.')
            return
        try:
            uid = caller_uid(sender)
        except Exception:
            invocation.return_dbus_error(BUS + '.Denied', 'Unable to verify the calling account.')
            return
        pending = True
        def authorized(bus, result, *_):
            nonlocal pending
            try:
                allowed, challenge, details = bus.call_finish(result).unpack()[0]
                if not allowed or caller_uid(sender) != uid:
                    raise PermissionError('Authorization denied')
                number = grant_logs(uid)
                invocation.return_value(GLib.Variant('(u)', (number,)))
            except Exception:
                invocation.return_dbus_error(BUS + '.Denied',
                    'Access was not enabled completely. Authentication may have been denied, or log metadata changed. Some grants may have applied.')
            finally:
                pending = False
        subject = ('system-bus-name', {'name': GLib.Variant('s', sender)})
        connection.call('org.freedesktop.PolicyKit1', '/org/freedesktop/PolicyKit1/Authority',
            'org.freedesktop.PolicyKit1.Authority', 'CheckAuthorization',
            GLib.Variant('((sa{sv})sa{ss}us)', (subject, ACTION, {}, 1, '')),
            GLib.VariantType.new('((bba{ss}))'), Gio.DBusCallFlags.NONE, 120000, None, authorized)

    info = Gio.DBusNodeInfo.new_for_xml(XML)
    connection.register_object(OBJECT, info.interfaces[0], method, None, None)
    owner = Gio.bus_own_name_on_connection(connection, BUS, Gio.BusNameOwnerFlags.NONE,
        None, lambda *_: loop.quit())
    connection.connect('closed', lambda *_: loop.quit())
    def idle_exit():
        if pending:
            return True
        loop.quit()
        return False
    GLib.timeout_add_seconds(30, idle_exit)
    try:
        loop.run()
    finally:
        Gio.bus_unown_name(owner)


if __name__ == '__main__':
    main()
