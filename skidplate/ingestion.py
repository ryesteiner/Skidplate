"""Cooperative ingestion: bounded retained queues and a per-tick work budget.

The GTK thread owns SQLite. Yielding regularly keeps its ownership simple without
unbounded producer queues or check_same_thread=False. A busy disk can still block
a single SQLite operation; diagnostics report stalls rather than promising none.
"""
from collections import deque
import time
from .core import parse_line


class Ingestion:
    def __init__(self):
        self.lines, self.events = deque(), deque()
        self.uncommitted = []

    def confirm(self):
        """Called only after SQLite commit; earlier events can now be released."""
        self.uncommitted.clear()

    def rollback(self):
        # A later failure rolls back the whole tick, not just the failed event.
        # Restore successfully consumed rows ahead of the remaining queue.
        self.events.extendleft(reversed(self.uncommitted))
        self.uncommitted.clear()

    def step(self, follower, assembler, consume, clock=time.monotonic):
        if not self.lines and not self.events:
            # Even 16KiB of newline-only input is bounded. Do not poll again
            # before draining it; pressure stays in the read-only source file.
            self.lines.extend(follower.poll(budget=16384))
        deadline, processed, skipped = clock() + .020, 0, 0
        while (self.lines or self.events) and processed < 64 and clock() < deadline:
            if self.events:
                consume(self.events[0])
                self.uncommitted.append(self.events.popleft())
            else:
                line = self.lines.popleft()
                try:
                    record = parse_line(line)
                    if record:
                        self.events.extend(assembler.feed(record))
                    elif line.strip(): skipped += 1
                except ValueError:
                    skipped += 1
            processed += 1
        if not self.lines and not self.events:
            # At most MAX_PENDING events; subsequent ticks drain before reading.
            self.events.extend(assembler.flush())
        return skipped
