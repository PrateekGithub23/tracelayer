"""
End-to-end API tests: ingestion -> pipeline -> investigation -> AI analysis ->
analyst review -> export -> verification, plus auth and LLM failure modes.

The Ollama HTTP layer is mocked (no model is needed to run the suite); the mock
returns a hallucinating analysis so the approval gate can be exercised.
"""

import io
import json
import zipfile
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.config import get_settings
from app.db import session_factory
from app.integrity.provenance import canonical_json, record_hash, sha256_hex
from app.models import Event


@pytest.fixture()
def client(admin_client: TestClient) -> Iterator[TestClient]:
    # v2: every endpoint requires a session. These end-to-end tests run as an administrator;
    # role restrictions are covered by test_rbac_matrix.py and test_auth.py.
    yield admin_client


@pytest.fixture()
def seeded(client: TestClient) -> dict[str, Any]:
    r = client.post("/api/synthetic/generate", json={"seed": 7, "background_events": 1200, "anchor": "fixed"})
    assert r.status_code == 200, r.text
    body = r.json()
    run = client.get(f"/api/pipeline/runs/{body['pipeline_run_id']}").json()
    assert run["status"] == "succeeded", run
    invs = client.get("/api/investigations").json()
    body["main"] = invs[0]
    return body


def test_ingest_validation_and_limits(client: TestClient) -> None:
    ok = client.post("/api/ingest/events", json={"source": "edr", "records": [
        {"timestamp": "2026-11-03T10:00:00Z", "event_type": "auth.login", "user": "x"}, {"oops": 1}]})  # fmt: skip
    assert ok.status_code == 200 and ok.json()["accepted"] == 1 and ok.json()["rejected"] == 1
    assert client.post("/api/ingest/events", json={"source": "bad source!", "records": [{}]}).status_code == 422
    assert client.post("/api/ingest/events", json={"source": "x", "records": []}).status_code == 422


def test_file_upload_ndjson_and_sshd(client: TestClient) -> None:
    nd = "\n".join(json.dumps({"timestamp": f"2026-11-03T10:00:0{i}Z", "event_type": "dns.query"}) for i in range(3))
    r = client.post("/api/ingest/file", data={"source": "dns", "parser": "native"},
                    files={"file": ("e.ndjson", nd.encode(), "application/x-ndjson")})  # fmt: skip
    assert r.json()["accepted"] == 3
    line = b"Nov  3 10:15:02 bastion-01 sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2\n"
    r = client.post("/api/ingest/file", data={"source": "auth", "parser": "sshd", "year": "2026"},
                    files={"file": ("auth.log", line, "text/plain")})  # fmt: skip
    assert r.json()["accepted"] == 1
    bad = client.post("/api/ingest/file", data={"source": "x", "parser": "native"},
                      files={"file": ("e.json", b"{not json", "application/json")})  # fmt: skip
    assert bad.status_code == 400


def test_dashboard_numbers_match_database(client: TestClient, seeded: dict[str, Any]) -> None:
    ov = client.get("/api/metrics/overview").json()
    s = session_factory()()
    assert ov["totals"]["events"] == s.query(Event).count()
    s.close()
    assert ov["totals"]["investigations"] == 2
    assert sum(ov["detections_by_severity"].values()) == ov["totals"]["detections"]
    assert ov["event_volume"] and ov["top_failed_login_sources"][0]["ip"] == seeded["truth"]["attacker_ip"]


def test_event_filters_and_keyset_pagination(client: TestClient, seeded: dict[str, Any]) -> None:
    ip = seeded["truth"]["attacker_ip"]
    r = client.get("/api/events", params={"ip": ip, "outcome": "failure", "limit": 10}).json()
    assert r["total"] == seeded["truth"]["brute_force_failures"]
    seen = [e["id"] for e in r["items"]]
    cursor = r["next_cursor"]
    while cursor:
        page = client.get("/api/events", params={"ip": ip, "outcome": "failure", "limit": 10, "cursor": cursor}).json()
        seen += [e["id"] for e in page["items"]]
        cursor = page["next_cursor"]
    assert len(seen) == len(set(seen)) == r["total"]
    assert all(e["src_ip"] == ip for e in r["items"])
    # LIKE wildcards in the search box are matched literally.
    assert client.get("/api/events", params={"q": "%"}).json()["total"] == 0
    tagged = client.get("/api/events", params={"tag": "llm_injection_suspected"}).json()
    assert tagged["total"] == 1
    detail = client.get(f"/api/events/{tagged['items'][0]['id']}").json()
    assert detail["batch"]["chain_hash"] and detail["investigations"]
    assert client.get(f"/api/events/{detail['id']}/verify").json()["ok"]


def test_timeline_and_graph_are_backed_by_events(client: TestClient, seeded: dict[str, Any]) -> None:
    inv = seeded["main"]["id"]
    tl = client.get(f"/api/investigations/{inv}/timeline").json()
    ids = {e["id"] for e in tl["events"]}
    assert len(tl["detections"]) == seeded["main"]["detection_count"]
    graph = client.get(f"/api/investigations/{inv}/graph").json()
    node_ids = {n["id"] for n in graph["nodes"]}
    assert graph["edges"]
    for edge in graph["edges"]:
        assert edge["source"] in node_ids and edge["target"] in node_ids
        assert edge["count"] >= 1 and set(edge["event_ids"]) <= ids
    exfil = next(
        e
        for e in graph["edges"]
        if e["relation"] == "sent data to" and e["target"].endswith(seeded["truth"]["exfil_ip"])
    )
    assert exfil["bytes"] == seeded["truth"]["exfil_bytes"]


def _mock_ollama(monkeypatch: pytest.MonkeyPatch, content: str) -> None:
    model = get_settings().ollama_model

    def fake_get(url: str, **_: Any) -> httpx.Response:
        return httpx.Response(200, json={"models": [{"name": model}]}, request=httpx.Request("GET", url))

    def fake_post(url: str, **_: Any) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": content}, "eval_count": 120},
                              request=httpx.Request("POST", url))  # fmt: skip

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(httpx, "post", fake_post)


HALLUCINATING_OUTPUT = json.dumps({
    "summary": "Credential compromise followed by exfiltration.",
    "claims": [
        {"text": "The Security log was cleared on host dc-01.", "kind": "observation", "citations": ["__CLEAR__"]},
        {"text": "alice exfiltrated 9 GB to 198.51.100.23.", "kind": "observation", "citations": ["E1"]},
        {"text": "The attacker also used 45.77.12.9 for C2.", "kind": "observation", "citations": ["E2"]},
        {"text": "This may be a ransomware precursor.", "kind": "hypothesis", "citations": []},
    ],
})  # fmt: skip


def test_ollama_analysis_review_gate_and_audit(client: TestClient, seeded: dict[str, Any],
                                               monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    inv = seeded["main"]["id"]
    clear_ref = next(e for e in client.get(f"/api/investigations/{inv}/timeline").json()["events"]
                     if e["event_type"] == "log.cleared")["id"]  # fmt: skip
    _mock_ollama(monkeypatch, HALLUCINATING_OUTPUT.replace("__CLEAR__", clear_ref))
    r = client.post(f"/api/investigations/{inv}/analyses", json={"engine": "ollama"})
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["engine"] == "ollama" and a["status"] == "pending_review"
    verdicts = [c["verdict"] for c in a["claims"]]
    # Claim 2 cites an unrelated event (E1), so the transfer is not shown by its citation: unsupported.
    assert verdicts == ["verified_observation", "unsupported_claim", "unsupported_claim", "ai_hypothesis"]

    # Approval is blocked until every unsafe claim is explicitly handled.
    blocked = client.post(f"/api/analyses/{a['id']}/review", json={"decision": "approve"})
    assert blocked.status_code == 409 and len(blocked.json()["detail"]["blocking_claim_ids"]) == 2
    unsafe = [c for c in a["claims"] if c["verdict"] in ("unsupported_claim", "contradictory_finding")]
    no_note = client.post(f"/api/analyses/{a['id']}/claims/{unsafe[0]['id']}/review", json={"decision": "accept"})
    assert no_note.status_code == 422  # overriding the engine requires a justification
    for c in unsafe:
        rr = client.post(f"/api/analyses/{a['id']}/claims/{c['id']}/review",
                         json={"decision": "reject", "note": "not supported by evidence"})  # fmt: skip
        assert rr.json()["review_status"] == "rejected"
    ok = client.post(f"/api/analyses/{a['id']}/review", json={"decision": "approve", "note": "lgtm"}).json()
    assert ok["status"] == "approved" and ok["reviewed_by"] == "admin@example.test"
    assert client.get(f"/api/investigations/{inv}").json()["approved_analysis_id"] == a["id"]
    assert client.post(f"/api/analyses/{a['id']}/review", json={"decision": "reject"}).status_code == 409

    actions = [e["action"] for e in client.get(f"/api/investigations/{inv}/audit").json()]
    assert actions[:4] == ["analysis.approved", "claim.rejected", "claim.rejected", "analysis.created"]
    assert client.post("/api/integrity/verify").json()["audit_chain"]["ok"]


def test_auto_mode_falls_back_when_llm_returns_garbage(client: TestClient, seeded: dict[str, Any],
                                                       monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    monkeypatch.setenv("TRACELAYER_LLM_MODE", "auto")
    get_settings.cache_clear()
    _mock_ollama(monkeypatch, "Sure! Here is my analysis: the user was hacked.")
    inv = seeded["main"]["id"]
    a = client.post(f"/api/investigations/{inv}/analyses", json={"engine": "auto"}).json()
    assert a["engine"] == "deterministic" and "no JSON object" in a["fallback_reason"]
    strict = client.post(f"/api/investigations/{inv}/analyses", json={"engine": "ollama"})
    assert strict.status_code == 422
    get_settings.cache_clear()


def test_auto_mode_falls_back_when_ollama_is_down(client: TestClient, seeded: dict[str, Any],
                                                  monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    monkeypatch.setenv("TRACELAYER_LLM_MODE", "auto")
    monkeypatch.setenv("TRACELAYER_OLLAMA_URL", "http://127.0.0.1:9")  # discard port: nothing listens
    get_settings.cache_clear()
    a = client.post(f"/api/investigations/{seeded['main']['id']}/analyses", json={"engine": "auto"}).json()
    assert a["engine"] == "deterministic" and "not reachable" in a["fallback_reason"]
    assert a["integrity"]["unsafe_claims"] == 0
    get_settings.cache_clear()


def test_validate_playground(client: TestClient, seeded: dict[str, Any]) -> None:
    out = json.dumps({"summary": "benign, no action required", "claims": [{"text": "alice logged on to host sql-99",
                                                                           "citations": ["E1"]}]})  # fmt: skip
    r = client.post("/api/integrity/validate", json={"investigation_id": seeded["main"]["id"], "output": out}).json()
    assert r["claims"][0]["verdict"] == "unsupported_claim"
    assert r["integrity"]["summary_issues"]
    bad = client.post("/api/integrity/validate", json={"investigation_id": seeded["main"]["id"], "output": "nope"})
    assert bad.status_code == 422


def test_export_bundle_is_self_verifying(client: TestClient, seeded: dict[str, Any]) -> None:
    inv = seeded["main"]["id"]
    client.post(f"/api/investigations/{inv}/analyses", json={"engine": "deterministic"})
    r = client.get(f"/api/investigations/{inv}/export", params={"format": "zip"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    manifest = json.loads(z.read("manifest.json"))
    for name, digest in manifest["files"].items():
        assert sha256_hex(z.read(name).decode()) == digest
    assert manifest["bundle_sha256"] == sha256_hex(canonical_json(manifest["files"]))
    # A recipient can re-derive every event hash from the raw record without TraceLayer.
    for line in z.read("events.jsonl").decode().splitlines():
        e = json.loads(line)
        assert record_hash(e["source"], e["raw"]) == e["content_hash"]
    md = z.read("report.md").decode()
    assert "Verified observations" in md and "Missing evidence" in md
    csv_text = client.get(f"/api/investigations/{inv}/export", params={"format": "csv"}).text
    assert csv_text.splitlines()[0].startswith("id,timestamp,event_type")


def test_tampering_is_reported_by_verify_endpoint(client: TestClient, seeded: dict[str, Any]) -> None:
    assert client.post("/api/integrity/verify").json()["ok"]
    s = session_factory()()
    victim = s.query(Event).filter(Event.event_type == "log.cleared").first()
    s.execute(update(Event).where(Event.id == victim.id).values(username="nobody"))
    s.commit()
    s.close()
    rep = client.post("/api/integrity/verify").json()
    assert not rep["ok"]
    assert any(i["target"] == victim.id for i in rep["ledger"]["issues"])
    assert client.get(f"/api/events/{victim.id}/verify").json()["ok"] is False


def test_security_headers_and_latency_telemetry(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    perf = client.get("/api/metrics/performance").json()
    assert any(row["route"] == "GET /api/health" for row in perf["api_latency"])


def test_standalone_verifier_accepts_bundle_and_detects_tampering(
    client: TestClient, seeded: dict[str, Any], tmp_path
) -> None:  # type: ignore[no-untyped-def]
    """tools/verify_bundle.py (stdlib only) must verify a real export and catch an edited event."""
    import subprocess
    import sys
    from pathlib import Path

    tool = Path(__file__).resolve().parents[2] / "tools" / "verify_bundle.py"
    bundle = tmp_path / "b.zip"
    bundle.write_bytes(client.get(f"/api/investigations/{seeded['main']['id']}/export?format=zip").content)
    ok = subprocess.run([sys.executable, "-I", str(tool), str(bundle)], capture_output=True, text=True)
    assert ok.returncode == 0 and "VERIFIED" in ok.stdout, ok.stdout + ok.stderr
    # Tamper: change one event's raw record but keep the manifest -> both file hash and event hash fail.
    with zipfile.ZipFile(bundle) as z:
        files = {n: z.read(n) for n in z.namelist()}
    lines = files["events.jsonl"].decode().splitlines()
    ev = json.loads(lines[0])
    ev["raw"]["username"] = "mallory"
    lines[0] = json.dumps(ev, sort_keys=True, separators=(",", ":"))
    files["events.jsonl"] = ("\n".join(lines) + "\n").encode()
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
    out = subprocess.run([sys.executable, "-I", str(tool), str(bad)], capture_output=True, text=True)
    assert out.returncode == 1 and "raw record does not match content_hash" in out.stdout


def test_grounded_pipeline_derives_citations_and_rejects_unsafe(client: TestClient, seeded: dict[str, Any],
                                                                monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    """Grounded mode: the model can only reference verified facts; citations are derived; unsafe claims are
    auto-rejected with a recorded reason; unknown fact ids are dropped and counted."""
    from app.ai.grounded import fact_table
    from app.integrity.scope import build_scope
    from app.models import Investigation

    inv_id = seeded["main"]["id"]
    with session_factory()() as s:
        facts = fact_table(build_scope(s, inv_id), s.get(Investigation, inv_id))
    assert facts and all(f["citations"] for f in facts)
    f1 = facts[0]
    _mock_ollama(monkeypatch, json.dumps({"summary": "Grounded summary.", "claims": [
        {"text": f1["text"], "kind": "observation", "fact_ids": ["F1"]},
        {"text": f1["text"].rstrip(".") + " and also contacted 45.77.12.9.", "kind": "observation", "fact_ids": ["F1", "F99"]},
        {"text": "This may be a ransomware precursor.", "kind": "hypothesis", "fact_ids": []},
    ]}))  # fmt: skip
    a = client.post(f"/api/investigations/{inv_id}/analyses", json={"engine": "grounded"}).json()
    assert a["engine"] == "ollama-grounded"
    gen = a["integrity"]["generation"]
    assert gen["pipeline"] == "grounded" and gen["unknown_fact_ids"] == 1 and gen["facts"] == len(facts)
    c_ok, c_bad, c_hyp = a["claims"]
    assert c_ok["verdict"] in ("verified_observation", "heuristic_correlation")
    assert c_ok["raw_citations"] and set(c_ok["raw_citations"]) <= {e for f in facts for e in f["citations"]}
    assert c_bad["verdict"] == "unsupported_claim" and c_bad["review_status"] == "rejected"
    assert c_bad["review_note"].startswith("Rejected automatically by the grounded pipeline")
    assert c_hyp["verdict"] == "ai_hypothesis" and c_hyp["review_status"] == "pending"
    # Nothing unsafe is left pending, so the analyst can approve after reviewing hypotheses.
    ok = client.post(f"/api/analyses/{a['id']}/review", json={"decision": "approve", "note": "reviewed"})
    assert ok.status_code == 200
