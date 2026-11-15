"""Detection rules (unit, with crafted events) and the engine on the full scenario."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.detection.base import EventView, is_external
from app.detection.engine import run_detection
from app.detection.rules import BruteForce, Exfiltration, ImpossibleTravel, LateralMovement, SuccessAfterFailures
from app.models import Detection, DetectionEvent
from app.synthetic.generator import Scenario
from tests.conftest import ingest_scenario

T0 = datetime(2026, 11, 3, 10, tzinfo=UTC)


def ev(i: int, minutes: float, **kw: object) -> EventView:
    base = dict(id=f"e{i}", timestamp=T0 + timedelta(minutes=minutes), event_type="auth.login", host="web-01",
                username="alice", src_ip="203.0.113.5", dst_ip=None, dst_port=None, process=None, command_line=None,
                outcome="failure", bytes_out=None, country=None, attributes={}, tags=[])  # fmt: skip
    base.update(kw)
    return EventView(**base)  # type: ignore[arg-type]


def test_brute_force_threshold_and_burst_split() -> None:
    nine = [ev(i, i * 0.5) for i in range(9)]
    assert BruteForce().evaluate(nine) == []
    two_bursts = [ev(i, i * 0.5) for i in range(12)] + [ev(100 + i, 60 + i * 0.5) for i in range(12)]
    found = BruteForce().evaluate(two_bursts)
    assert len(found) == 2
    assert all(len(c.event_ids) == 12 for c in found)


def test_success_after_failures() -> None:
    evs = [ev(i, i) for i in range(6)] + [ev(99, 7, outcome="success")]
    (c,) = SuccessAfterFailures().evaluate(evs)
    assert "after 6 failed" in c.summary and c.event_ids[-1] == "e99"
    late = [ev(i, i) for i in range(6)] + [ev(99, 60, outcome="success")]  # outside the 30 min lookback
    assert SuccessAfterFailures().evaluate(late) == []


def test_impossible_travel() -> None:
    fast = [ev(1, 0, outcome="success", country="CA"), ev(2, 45, outcome="success", country="RU")]
    assert len(ImpossibleTravel().evaluate(fast)) == 1
    slow = [ev(1, 0, outcome="success", country="CA"), ev(2, 60 * 20, outcome="success", country="RU")]
    assert ImpossibleTravel().evaluate(slow) == []


def test_lateral_movement_requires_five_hosts_in_window() -> None:
    four = [ev(i, i * 3, outcome="success", host=f"h{i}") for i in range(4)]
    assert LateralMovement().evaluate(four) == []
    five = [ev(i, i * 3, outcome="success", host=f"h{i}") for i in range(5)]
    assert len(LateralMovement().evaluate(five)) == 1
    spread = [ev(i, i * 20, outcome="success", host=f"h{i}") for i in range(5)]  # 80 minutes > 30 minute window
    assert LateralMovement().evaluate(spread) == []


def test_exfiltration_needs_external_destination_and_volume() -> None:
    flows = [ev(i, i, event_type="network.flow", dst_ip="198.51.100.23", bytes_out=10 * 1024 * 1024)
             for i in range(6)]  # fmt: skip
    (c,) = Exfiltration().evaluate(flows)
    assert c.severity == "high"
    internal = [ev(i, i, event_type="network.flow", dst_ip="10.0.0.5", bytes_out=10 * 1024 * 1024) for i in range(6)]
    assert Exfiltration().evaluate(internal) == []
    assert is_external("8.8.8.8") and is_external("203.0.113.1") and not is_external("192.168.1.1")


def test_scenario_recall_and_no_false_positives(db: Session, scenario: Scenario) -> None:
    ingest_scenario(db, scenario)
    stats = run_detection(db)
    db.commit()
    fired = set(db.scalars(select(Detection.rule_id).distinct()))
    assert set(scenario.truth["expected_rules"]) <= fired
    attack = {scenario.truth[k] for k in ("attacker_ip", "exfil_ip", "ssh_attacker_ip", "victim")} | {"sam"}
    fps = [d.summary for d in db.scalars(select(Detection)) if not any(e["value"] in attack for e in d.entities)]
    assert fps == []
    assert stats["created"] == db.scalar(select(func.count()).select_from(Detection))


def test_detection_is_idempotent(db: Session, scenario: Scenario) -> None:
    ingest_scenario(db, scenario)
    run_detection(db)
    db.commit()
    links = db.scalar(select(func.count()).select_from(DetectionEvent))
    again = run_detection(db)
    db.commit()
    assert again["created"] == 0 and again["updated"] == 0
    assert db.scalar(select(func.count()).select_from(DetectionEvent)) == links


def test_slow_trickle_of_failures_is_not_brute_force() -> None:
    """Regression (found at 100k scale): gap-chained bursts let a slow trickle accumulate into an alert."""
    trickle = [ev(i, i * 4) for i in range(40)]  # one failure every 4 minutes for 2.5 hours
    assert BruteForce().evaluate(trickle) == []


def test_typos_followed_by_success_do_not_count_as_a_run() -> None:
    """Regression: each failure is followed by a successful login (a typo), so there is no run of failures."""
    evs = []
    for i in range(8):
        evs += [ev(2 * i, i * 3, outcome="failure"), ev(2 * i + 1, i * 3 + 0.2, outcome="success")]
    assert SuccessAfterFailures().evaluate(evs) == []


def test_no_false_positives_at_dense_background_scale() -> None:
    """At 5x the default background density, only attack-related detections may fire."""
    from app.detection.engine import run_rules
    from app.ingestion.parsers import get_parser
    from app.synthetic.generator import generate

    sc = generate(seed=3, background_events=60_000)
    parsers = (("native", sc.native), ("sshd", sc.sshd), ("winsec", sc.winsec))
    views = []
    for name, records in parsers:
        p = get_parser(name)
        for i, r in enumerate(records):
            n = p.parse(p.to_raw(r, {"year": 2026}))
            views.append(EventView(f"{name}{i}", n.timestamp, n.event_type, n.host, n.username, n.src_ip, n.dst_ip,
                                   n.dst_port, n.process, n.command_line, n.outcome, n.bytes_out, n.country,
                                   n.attributes, n.tags))  # fmt: skip
    views.sort(key=lambda e: e.timestamp)
    candidates, _ = run_rules(views)
    attack = {sc.truth[k] for k in ("attacker_ip", "exfil_ip", "ssh_attacker_ip", "victim")} | {"sam"}
    fps = [c.summary for c in candidates if not any(e["value"] in attack for e in c.entities)]
    assert fps == []
    assert set(sc.truth["expected_rules"]) <= {c.rule_id for c in candidates}
