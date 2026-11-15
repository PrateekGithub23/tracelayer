"""Evidence Integrity Engine: adversarial suite thresholds and targeted validator behaviour."""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import deterministic
from app.ai.service import summary_issues
from app.evaluation.suite import run_suite
from app.integrity.scope import build_scope
from app.integrity.validator import (
    CONTRADICTORY,
    HYPOTHESIS,
    UNSAFE,
    UNSUPPORTED,
    VERIFIED,
    ClaimInput,
    validate_all,
    validate_claim,
)
from app.models import Detection, Investigation


@pytest.fixture(scope="module")
def suite_report() -> dict:
    return run_suite()


def test_no_adversarial_claim_is_accepted(suite_report: dict) -> None:
    s = suite_report["summary"]
    failures = [
        c
        for c in suite_report["cases"]
        if c["adversarial"] and c["actual"] in ("verified_observation", "heuristic_correlation")
    ]
    assert s["unsafe_acceptance"] == 0, failures


def test_legitimate_claims_are_not_rejected(suite_report: dict) -> None:
    assert suite_report["summary"]["false_rejection"] == 0, [
        c for c in suite_report["cases"] if not c["adversarial"] and c["actual"] in UNSAFE
    ]


def test_suite_accuracy_and_structural_checks(suite_report: dict) -> None:
    s = suite_report["summary"]
    assert s["accuracy"] >= 0.95
    assert s["structural_passed"] == s["structural_total"]
    assert s["deterministic_baseline_unsafe"] == 0


def _main_scope(db: Session):  # type: ignore[no-untyped-def]
    det = db.scalar(select(Detection).where(Detection.rule_id == "TL-EXFIL-001"))
    return build_scope(db, det.investigation_id)


def test_deterministic_analyst_is_fully_supported(loaded_db: Session) -> None:
    for inv in loaded_db.scalars(select(Investigation)):
        scope = build_scope(loaded_db, inv.id)
        out, _ = deterministic.analyze(scope, inv)
        results, summary = validate_all([ClaimInput(c.text, c.kind, c.citations) for c in out.claims], scope)
        assert summary["unsafe_claims"] == 0, [(r.text, r.reasons) for r in results if r.verdict in UNSAFE]
        assert summary["claims"] >= 2
        assert summary_issues(out.summary, scope) == []


def test_full_event_ids_are_accepted_as_citations(loaded_db: Session) -> None:
    scope = _main_scope(loaded_db)
    clear = next(e for e in scope.ordered() if e.event_type == "log.cleared")
    r = validate_claim(ClaimInput("The Security log was cleared on host dc-01.", "observation", [clear.id]), scope)
    assert r.verdict == VERIFIED and r.citations == [clear.id]


def test_reasons_explain_contradiction(loaded_db: Session) -> None:
    scope = _main_scope(loaded_db)
    flows = [scope.id_to_ref[e.id] for e in scope.ordered() if e.dst_ip == "198.51.100.23"]
    r = validate_claim(ClaimInput("Host file-01 sent 9 GB to 198.51.100.23.", "observation", flows), scope)
    assert r.verdict == CONTRADICTORY
    assert any("384.0 MB" in x for x in r.reasons)


def test_declared_hypothesis_without_citations(loaded_db: Session) -> None:
    scope = _main_scope(loaded_db)
    r = validate_claim(ClaimInput("The actor could be an insider.", "hypothesis", []), scope)
    assert r.verdict == HYPOTHESIS
    r2 = validate_claim(ClaimInput("The actor is an insider.", "observation", []), scope)
    assert r2.verdict == UNSUPPORTED
