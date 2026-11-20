"""STAGE 7 - request statistics.

A tiny thread-safe set of counters. Several client threads update them at the
same time, so every update goes through a lock.
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from typing import Dict


class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Counter = Counter()
        self._started = time.time()

    def incr(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] += amount

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def format(self) -> str:
        data = self.snapshot()
        uptime = time.time() - self._started
        lines = [f"--- proxy statistics (uptime {uptime:.0f}s) ---"]
        for name in sorted(data):
            lines.append(f"{name:>24}: {data[name]}")
        hits = data.get("cache_hits", 0)
        misses = data.get("cache_misses", 0)
        if hits + misses:
            lines.append(f"{'cache hit ratio':>24}: {hits / (hits + misses):.0%}")
        return "\n".join(lines)
