"""Correlation: clustering logic, entity suppression, and investigation lifecycle."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.correlation.engine import cluster_detections, run_correlation, score_cluster
from app.ingestion.pipeline import ingest_records
from app.models import Detection, Investigation, InvestigationEvent
from app.synthetic.generator import Scenario

T0 = datetime(2026, 11, 3, 10, tzinfo=UTC)


def det(i: str, minutes: float, entities: list[tuple[str, str]], severity: str = "high",
        tactic: str = "execution") -> Detection:  # fmt: skip
    t = T0 + timedelta(minutes=minutes)
    return Detection(id=i, dedup_key=i, rule_id="R", rule_name="R", severity=severity, confidence=0.8, tactic=tactic,
                     technique="T", first_seen=t, last_seen=t + timedelta(minutes=5), summary="",
                     entities=[{"type": k, "value": v} for k, v in entities])  # fmt: skip


def test_shared_entity_within_window_links_transitively() -> None:
    a = det("a", 0, [("user", "alice")])
    b = det("b", 30, [("user", "alice"), ("host", "web-01")])
    c = det("c", 60, [("host", "web-01")])
    d = det("d", 30, [("user", "bob")])
    clusters, _ = cluster_detections([a, b, c, d], timedelta(minutes=120))
    assert sorted(sorted(x.id for x in cl) for cl in clusters) == [["a", "b", "c"], ["d"]]


def test_window_separates_distant_detections() -> None:
    a = det("a", 0, [("user", "alice")])
    b = det("b", 600, [("user", "alice")])
    clusters, _ = cluster_detections([a, b], timedelta(minutes=120))
    assert len(clusters) == 2


def test_ubiquitous_entity_is_suppressed() -> None:
    dets = [det(f"d{i}", i, [("host", "dns-01"), ("user", f"u{i}")]) for i in range(25)]
    clusters, suppressed = cluster_detections(dets, timedelta(minutes=120))
    assert suppressed == ["host:dns-01"]
    assert len(clusters) == 25


def test_score_rewards_kill_chain_breadth() -> None:
    single = score_cluster([det("a", 0, [], tactic="execution")])
    chain = score_cluster([det("a", 0, [], tactic="credential-access"), det("b", 5, [], tactic="execution"),
                           det("c", 9, [], tactic="exfiltration")])  # fmt: skip
    assert chain["score"] > single["score"]
    assert chain["tactics"] == ["credential-access", "execution", "exfiltration"]


def test_scenario_produces_separate_investigations(loaded_db: Session, scenario: Scenario) -> None:
    invs = list(loaded_db.scalars(select(Investigation).order_by(Investigation.score.desc())))
    assert len(invs) == 2
    main, ssh = invs
    assert main.severity == "critical" and len(main.tactics) >= 6
    assert any(e["value"] == scenario.truth["ssh_attacker_ip"] for e in ssh.entities)
    # The lone low-severity whoami by "sam" stays an unassigned detection.
    lone = loaded_db.scalars(select(Detection).where(Detection.investigation_id.is_(None))).all()
    assert [d.rule_id for d in lone] == ["TL-EXEC-001"]
    roles = dict(loaded_db.execute(select(InvestigationEvent.role, func.count())
                                   .where(InvestigationEvent.investigation_id == main.id)
                                   .group_by(InvestigationEvent.role)).all())  # fmt: skip
    assert roles["evidence"] > 50 and roles["context"] > 0


def test_rerun_is_stable_and_late_evidence_extends(loaded_db: Session, scenario: Scenario) -> None:
    before = loaded_db.scalar(select(func.count()).select_from(Investigation))
    assert run_correlation(loaded_db)["investigations_created"] == 0
    # New activity by the victim shortly after the intrusion joins the existing investigation.
    main = max(loaded_db.scalars(select(Investigation)), key=lambda i: i.score)
    t = main.last_seen + timedelta(minutes=10)
    ingest_records(loaded_db, [{"timestamp": (t + timedelta(seconds=i)).isoformat(), "event_type": "process.start",
                                "user": "alice", "host": "app-02",
                                "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 out.dmp full"}
                               for i in range(2)], source="late", parser_name="native")  # fmt: skip
    from app.detection.engine import run_detection

    run_detection(loaded_db)
    loaded_db.flush()
    stats = run_correlation(loaded_db)
    loaded_db.commit()
    assert stats["investigations_created"] == 0 and stats["investigations_extended"] == 1
    assert loaded_db.scalar(select(func.count()).select_from(Investigation)) == before
