"""
In-process sliding-window rate limiter for authentication endpoints.

Keys are combined per client IP *and* per target account, so one attacker cannot brute-force a single
account from many addresses without hitting the per-account limit, and cannot spray many accounts from one
address without hitting the per-IP limit. We deliberately do not lock accounts: lockout lets anyone deny
service to a known user by failing their login on purpose.

Limitation (documented): state is per process and resets on restart. TraceLayer runs a single worker.
"""

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_s: float) -> float | None:
        """Record a hit. Returns None if allowed, or seconds until the next allowed attempt."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window_s:
                q.popleft()
            if len(q) >= limit:
                return max(0.0, q[0] + window_s - now)
            q.append(now)
            if len(self._hits) > 50_000:  # bound memory under a key-flooding attack
                for k in [k for k, v in self._hits.items() if not v][:10_000]:
                    del self._hits[k]
            return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()

# (limit, window seconds)
LOGIN_PER_IP = (30, 15 * 60)
LOGIN_PER_ACCOUNT = (10, 15 * 60)
SENSITIVE_PER_IP = (10, 15 * 60)  # registration, recovery, password change
