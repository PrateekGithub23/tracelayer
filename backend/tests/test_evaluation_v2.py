"""Guards on the integrity engine's measured behaviour (does not tune anything: it fails if behaviour regresses)."""

from typing import Any

import pytest

from app.evaluation.suite import run_suite


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    return run_suite(include_heldout_v2=True)


def test_no_dangerous_false_verifications_on_any_set(report: dict[str, Any]) -> None:
    for name, m in report["sets"].items():
        assert m["false_verification"] == 0, f"{name}: adversarial claim accepted as verified/correlated"


def test_development_and_regression_sets(report: dict[str, Any]) -> None:
    assert report["sets"]["dev_v1"]["accuracy"] == 1.0
    assert report["sets"]["regression_v1_heldout"]["accuracy"] == 1.0
    assert report["sets"]["dev_v2"]["accuracy"] == 1.0
    assert report["sets"]["dev_v3"]["accuracy"] == 1.0
    assert report["summary"]["structural_passed"] == report["summary"]["structural_total"]
    assert report["summary"]["deterministic_baseline_unsafe"] == 0


def test_heldout_v2_recorded_result_does_not_regress(report: dict[str, Any]) -> None:
    """Recorded once at commit 7e5f3d0: 39/40. This guards against regression; it is not a tuning target."""
    ho = report["sets"]["heldout_v2"]
    assert ho["cases"] == 40 and ho["accuracy"] >= 0.975 and ho["false_rejection"] == 0


def test_explainable_trace_and_review_flag(report: dict[str, Any]) -> None:
    rows = report["set_cases"]["dev_v2"]
    assert all(r["requires_review"] is not None for r in rows)
    assert all(
        r["requires_review"] for r in rows if r["actual"] not in ("verified_observation", "heuristic_correlation")
    )
