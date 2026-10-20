"""Private bounded diagnostics without raw events, exception values or locals.

Tracebacks contain code locations, which can reveal the installation path. They
never include log field values or source lines. Hang dumps use faulthandler's C
watchdog so a blocked GTK thread can still leave evidence. No automatic upload.
"""
import faulthandler
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time
import traceback


class Diagnostics:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = self.directory / 'diagnostics.jsonl'
        self.fault_path = self.directory / 'faults.log'
        self.lock = threading.Lock()
        self.last_sample = 0
        self.old_hook, self.old_thread_hook = sys.excepthook, threading.excepthook
        self.fault = self.open_private(self.fault_path)
        if sys.version_info >= (3, 14):
            faulthandler.enable(self.fault, c_stack=False)
        else:
            faulthandler.enable(self.fault)
        sys.excepthook = self.exception_hook
        threading.excepthook = lambda args: self.exception_hook(args.exc_type, args.exc_value, args.exc_traceback)
        self.record('startup', pid=os.getpid())

    @staticmethod
    def open_private(path):
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            os.close(fd)
            raise PermissionError('Diagnostic file must be private and owned')
        return os.fdopen(fd, 'a', buffering=1)

    def record(self, kind, **values):
        with self.lock:
            # Truncating through a checked descriptor cannot follow a replacement
            # symlink. Keep one bounded rolling diagnostic stream, no raw data.
            with self.open_private(self.path) as stream:
                if os.fstat(stream.fileno()).st_size > 1024 * 1024:
                    os.ftruncate(stream.fileno(), 0)
                stream.write(json.dumps(dict(time=time.time(), kind=kind, **values)) + '\n')

    def exception_hook(self, kind, value, tb):
        self.record('exception', exception=kind.__name__, frames=[
            {'file': frame.filename, 'line': frame.lineno, 'function': frame.name}
            for frame in traceback.extract_tb(tb, limit=24)])
        # Do not call the default hook: exception messages may contain audit data.

    def pulse(self, **counts):
        """Reset a one-shot hang timer; sample current RSS once per minute."""
        faulthandler.dump_traceback_later(30, repeat=False, file=self.fault)
        if os.fstat(self.fault.fileno()).st_size > 1024 * 1024:
            os.ftruncate(self.fault.fileno(), 0)
        if time.monotonic() - self.last_sample >= 60:
            self.last_sample = time.monotonic()
            rss = 0
            try:
                for line in Path('/proc/self/status').read_text().splitlines():
                    if line.startswith('VmRSS:'): rss = int(line.split()[1])
            except (OSError, ValueError):
                pass
            self.record('health', rss_kib=rss, threads=threading.active_count(), **counts)

    def close(self):
        faulthandler.cancel_dump_traceback_later()
        faulthandler.disable()
        sys.excepthook, threading.excepthook = self.old_hook, self.old_thread_hook
        self.record('shutdown')
        self.fault.close()
