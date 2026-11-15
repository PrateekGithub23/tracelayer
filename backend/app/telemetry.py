"""
In-process API latency telemetry.

A bounded ring buffer per route gives p50/p95/p99 for the performance
dashboard without Prometheus. It resets on restart, which is fine: the durable
performance record lives in pipeline_runs, ingest_batches and reports.
"""

import threading
from collections import defaultdict, deque
from statistics import quantiles
from typing import Any

_LOCK = threading.Lock()
_SAMPLES: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=2000))
_ERRORS: dict[str, int] = defaultdict(int)


def observe(route: str, ms: float, status: int) -> None:
    with _LOCK:
        _SAMPLES[route].append(ms)
        if status >= 500:
            _ERRORS[route] += 1


def percentile_table() -> list[dict[str, Any]]:
    with _LOCK:
        snapshot = {k: list(v) for k, v in _SAMPLES.items()}
        errors = dict(_ERRORS)
    rows = []
    for route, samples in snapshot.items():
        if not samples:
            continue
        s = sorted(samples)
        qs = quantiles(s, n=100, method="inclusive") if len(s) > 1 else [s[0]] * 99
        rows.append({"route": route, "count": len(s), "p50_ms": round(qs[49], 2), "p95_ms": round(qs[94], 2),
                     "p99_ms": round(qs[98], 2), "max_ms": round(s[-1], 2), "errors_5xx": errors.get(route, 0)})  # fmt: skip
    return sorted(rows, key=lambda r: -r["count"])
