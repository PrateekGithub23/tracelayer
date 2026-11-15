"""Case workflow: transitions, ownership, segregation of duties, concurrency, collaboration, evidence safety."""

import threading
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db import session_scope
from app.export import md
from app.main import create_app
from app.models import Event, InvestigationEvent
from tests.conftest import PASSWORDS, login, make_user


@pytest.fixture()
def team(admin_client: TestClient) -> Iterator[dict[str, Any]]:
    r = admin_client.post("/api/synthetic/generate", json={"seed": 7, "background_events": 800, "anchor": "fixed"})
    assert r.status_code == 200, r.text
    inv = admin_client.get("/api/investigations").json()[0]
    ids = {"alice": make_user("analyst", "alice@example.test", PASSWORDS["analyst"], display_name="Alice"),
           "bob": make_user("analyst", "bob@example.test", PASSWORDS["analyst"], display_name="Bob"),
           "vic": make_user("viewer", "vic@example.test", PASSWORDS["viewer"])}  # fmt: skip
    clients = {}
    for name in ("alice", "bob", "vic"):
        c = TestClient(create_app())
        c.__enter__()
        login(c, f"{name}@example.test", PASSWORDS["viewer" if name == "vic" else "analyst"])
        clients[name] = c
    yield {"admin": admin_client, **clients, "ids": ids, "inv": inv}
    for c in clients.values():
        c.__exit__(None, None, None)


def _patch(c: TestClient, inv_id: str, **body: Any) -> Any:
    if "expected_version" not in body:
        body["expected_version"] = c.get(f"/api/investigations/{inv_id}").json()["version"]
    return c.patch(f"/api/investigations/{inv_id}", json=body)


def test_full_lifecycle_with_segregation_of_duties(team: dict[str, Any]) -> None:
    a, b, inv = team["alice"], team["bob"], team["inv"]["id"]
    assert team["inv"]["status"] == "new" and team["inv"]["priority"] == "P1"  # critical -> P1
    v = a.get(f"/api/investigations/{inv}").json()["version"]
    assert a.post(f"/api/investigations/{inv}/assign-to-me?expected_version={v}").json()["assignee_name"] == "Alice"
    assert _patch(a, inv, status="triaged").status_code == 422  # a reason is mandatory
    assert _patch(a, inv, status="resolved", reason="skip").status_code == 409  # new -> resolved is not allowed
    assert _patch(a, inv, status="triaged", reason="confirmed real").status_code == 200
    assert _patch(a, inv, status="investigating", reason="working it").status_code == 200
    assert _patch(a, inv, status="awaiting_review", reason="done").status_code == 422  # needs a reviewer
    me = team["ids"]["alice"]
    assert _patch(a, inv, reviewer_id=me).status_code == 200
    assert _patch(a, inv, status="awaiting_review", reason="done").json()["detail"].startswith("the reviewer must be")
    assert (
        _patch(a, inv, reviewer_id=team["ids"]["bob"], status="awaiting_review", reason="please review").status_code
        == 200
    )
    # The assignee cannot approve their own work.
    r = _patch(a, inv, status="resolved", resolution="true_positive", reason="self-approve")
    assert r.status_code == 403
    assert _patch(b, inv, status="resolved", reason="ok").status_code == 422  # resolution code required
    done = _patch(b, inv, status="resolved", resolution="true_positive", reason="evidence holds up")
    assert done.status_code == 200 and done.json()["resolution"] == "true_positive"
    assert _patch(a, inv, status="closed", reason="reported").status_code == 200
    # Reopen keeps history and counts.
    re = _patch(a, inv, status="investigating", reason="new IOC seen")
    assert re.status_code == 200 and re.json()["reopen_count"] == 1 and re.json()["closed_at"] is None
    actions = [e["action"] for e in a.get(f"/api/investigations/{inv}/activity").json()]
    assert actions[0] == "case.reopened" and actions.count("case.status_changed") == 5
    entry = next(e for e in a.get(f"/api/investigations/{inv}/activity").json() if e["action"] == "case.reopened")
    assert entry["details"]["reason"] == "new IOC seen" and "alice@example.test" in entry["actor"]


def test_horizontal_privilege_escalation_is_blocked(team: dict[str, Any]) -> None:
    a, b, admin, inv = team["alice"], team["bob"], team["admin"], team["inv"]["id"]
    assert _patch(a, inv, assignee_id=team["ids"]["alice"]).status_code == 200
    # Bob cannot change, take over, or reassign Alice's case.
    assert _patch(b, inv, priority="P4").status_code == 403
    assert _patch(b, inv, assignee_id=team["ids"]["bob"]).status_code == 403
    assert b.post(f"/api/investigations/{inv}/assign-to-me?expected_version=99").status_code == 409
    # Viewers cannot be assignees; the administrator can reassign.
    assert _patch(admin, inv, assignee_id=team["ids"]["vic"]).status_code == 422
    assert _patch(admin, inv, assignee_id=team["ids"]["bob"]).json()["assignee_name"] == "Bob"
    assert _patch(b, inv, priority="P2").status_code == 200
    # Alice can still comment on (but not modify) a case she no longer owns.
    assert a.post(f"/api/investigations/{inv}/comments", json={"body": "FYI: seen this IP before"}).status_code == 201


def test_stale_writes_are_rejected(team: dict[str, Any]) -> None:
    a, admin, inv = team["alice"], team["admin"], team["inv"]["id"]
    v = a.get(f"/api/investigations/{inv}").json()["version"]
    assert _patch(admin, inv, expected_version=v, priority="P2").status_code == 200
    stale = _patch(a, inv, expected_version=v, priority="P3")
    assert stale.status_code == 409 and stale.json()["detail"]["current_version"] == v + 1
    assert a.get(f"/api/investigations/{inv}").json()["priority"] == "P2"  # nothing was overwritten


def test_concurrent_writers_one_wins(team: dict[str, Any]) -> None:
    """Two analysts submit at the same instant with the same version: exactly one succeeds."""
    admin, inv = team["admin"], team["inv"]["id"]
    v = admin.get(f"/api/investigations/{inv}").json()["version"]
    other = TestClient(create_app())
    other.__enter__()
    login(other, "alice@example.test", PASSWORDS["analyst"])
    barrier, codes = threading.Barrier(2), []

    def go(c: TestClient, prio: str) -> None:
        barrier.wait()
        codes.append(c.patch(f"/api/investigations/{inv}", json={"expected_version": v, "priority": prio}).status_code)

    ts = [threading.Thread(target=go, args=(admin, "P2")), threading.Thread(target=go, args=(other, "P4"))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    other.__exit__(None, None, None)
    assert sorted(codes) == [200, 409]
    assert admin.get(f"/api/investigations/{inv}").json()["version"] == v + 1


def test_closing_never_touches_evidence_and_freezes_scope(team: dict[str, Any]) -> None:
    admin, inv = team["admin"], team["inv"]["id"]

    def snapshot() -> tuple[int, int, str]:
        with session_scope() as s:
            n = s.scalar(
                select(func.count()).select_from(InvestigationEvent).where(InvestigationEvent.investigation_id == inv)
            )
            hashes = sorted(s.scalars(select(Event.content_hash)))
        return n or 0, len(hashes), "".join(hashes)

    before = snapshot()
    for st, extra in (("triaged", {}), ("resolved", {"resolution": "true_positive"}), ("closed", {})):
        assert _patch(admin, inv, status=st, reason=f"to {st}", **extra).status_code == 200
    assert snapshot() == before
    # New activity from the same attacker arrives: correlation must not extend a closed case.
    assert (
        admin.post("/api/synthetic/generate", json={"seed": 8, "background_events": 200, "anchor": "fixed"}).status_code
        == 200
    )
    assert snapshot()[0] == before[0]
    assert admin.get(f"/api/investigations/{inv}").json()["status"] == "closed"
    assert admin.get(f"/api/investigations/{inv}/verify-scope").status_code in (404, 405)  # no hidden mutation route


def test_comments_notes_and_ownership(team: dict[str, Any]) -> None:
    a, b, vic, inv = team["alice"], team["bob"], team["vic"], team["inv"]["id"]
    c = a.post(f"/api/investigations/{inv}/comments", json={"kind": "note", "body": "Initial hypothesis"}).json()
    assert vic.post(f"/api/investigations/{inv}/comments", json={"body": "hi"}).status_code == 403
    assert b.patch(f"/api/investigations/{inv}/comments/{c['id']}", json={"body": "edited by bob"}).status_code == 403
    assert b.delete(f"/api/investigations/{inv}/comments/{c['id']}").status_code == 403
    assert (
        a.patch(f"/api/investigations/{inv}/comments/{c['id']}", json={"body": "Refined hypothesis"}).status_code == 200
    )
    assert a.delete(f"/api/investigations/{inv}/comments/{c['id']}").status_code == 200
    listed = vic.get(f"/api/investigations/{inv}/comments").json()
    assert listed[0]["deleted"] and listed[0]["body"] is None
    acts = [e["action"] for e in vic.get(f"/api/investigations/{inv}/activity").json()]
    assert acts[:3] == ["note.deleted", "note.edited", "note.added"]


def test_pinned_evidence_and_saved_filters(team: dict[str, Any]) -> None:
    a, b, inv = team["alice"], team["bob"], team["inv"]["id"]
    ev = a.get(f"/api/events?investigation_id={inv}&limit=1").json()["items"][0]["id"]
    assert a.post(f"/api/investigations/{inv}/evidence", json={"event_id": ev, "note": "key logon"}).status_code == 201
    assert a.post(f"/api/investigations/{inv}/evidence", json={"event_id": ev}).status_code == 409
    assert a.post(f"/api/investigations/{inv}/evidence", json={"event_id": "evt_missing"}).status_code == 404
    pins = team["vic"].get(f"/api/investigations/{inv}/evidence").json()
    assert pins[0]["event_id"] == ev and pins[0]["added_by"] == "Alice" and len(pins[0]["content_hash"]) == 64
    f = a.post(
        "/api/filters", json={"name": "crit", "scope": "investigations", "params": {"severity": "critical"}}
    ).json()
    assert [x["id"] for x in a.get("/api/filters").json()] == [f["id"]]
    assert b.get("/api/filters").json() == []  # private
    assert b.delete(f"/api/filters/{f['id']}").status_code == 404  # IDOR: indistinguishable from missing
    assert a.delete(f"/api/filters/{f['id']}").status_code == 200


def test_queue_views(team: dict[str, Any]) -> None:
    a, b, inv = team["alice"], team["bob"], team["inv"]["id"]
    assert inv in {i["id"] for i in a.get("/api/investigations?view=unassigned").json()}
    _patch(a, inv, assignee_id=team["ids"]["alice"])
    _patch(a, inv, status="investigating", reason="starting")
    _patch(a, inv, reviewer_id=team["ids"]["bob"], status="awaiting_review", reason="review pls")
    assert [i["id"] for i in a.get("/api/investigations?view=mine").json()] == [inv]
    assert [i["id"] for i in b.get("/api/investigations?view=needs_review").json()] == [inv]
    assert b.get("/api/queues").json()["needs_review"] == 1
    assert a.get("/api/investigations?view=recent").json()[0]["id"] == inv


def test_export_includes_case_state_and_escapes_markdown(team: dict[str, Any]) -> None:
    a, inv = team["alice"], team["inv"]["id"]
    a.post(f"/api/investigations/{inv}/comments", json={"kind": "note", "body": "[click](javascript:alert(1)) | <img>"})
    report = a.get(f"/api/investigations/{inv}/export?format=md").text
    assert "Analyst notes" in report and "[click](javascript" not in report and "<img>" not in report
    assert md("a|b[c](d)") == "a\\|b\\[c\\](d)"
    assert team["vic"].get(f"/api/investigations/{inv}/export?format=md").status_code == 403
