"""High-resolution monotonic timing with named sections.

All timers use ``time.perf_counter_ns``.  ``SectionTimer`` is the
non-invasive instrumentation primitive used by the scheme adapters for the
phase breakdown experiments (Exp08) and by the experiment runners for
end-to-end accounting.
"""

from contextlib import contextmanager
from time import perf_counter_ns


class SectionTimer:
    """Accumulate wall time under named sections.

    Sections are mutually independent accumulators (not nested scopes), so the
    same name can be used repeatedly; each ``section()`` block adds its own
    duration.  ``total()`` returns the sum of the recorded sections.
    """

    def __init__(self):
        self._sections = {}
        self._order = []

    @contextmanager
    def section(self, name):
        start = perf_counter_ns()
        try:
            yield
        finally:
            elapsed = perf_counter_ns() - start
            self._sections[name] = self._sections.get(name, 0) + elapsed
            if name not in self._order:
                self._order.append(name)

    def get(self, name):
        return self._sections.get(name, 0)

    def names(self):
        return list(self._order)

    def as_dict(self, scale=1.0):
        return {name: value * scale for name, value in self._sections.items()}

    def total(self):
        return sum(self._sections.values())


class Stopwatch:
    """Simple monotonic stopwatch returning elapsed nanoseconds."""

    __slots__ = ("_start",)

    def __init__(self):
        self._start = perf_counter_ns()

    def elapsed_ns(self):
        return perf_counter_ns() - self._start

    def elapsed_ms(self):
        return (perf_counter_ns() - self._start) / 1_000_000.0
