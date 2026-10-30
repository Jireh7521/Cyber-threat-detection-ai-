"""Tiny in-memory sliding-window rate limiter (per client IP).

Good enough for a single-process deployment. For several workers/servers,
swap this for Redis or an API gateway limit.
"""
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max_requests:
            return False
        q.append(now)
        # Don't let idle keys pile up forever.
        if len(self._hits) > 10_000:
            self._hits = defaultdict(deque, {k: v for k, v in self._hits.items() if v})
        return True
