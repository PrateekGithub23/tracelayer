"""
Build the public demo snapshot: real API responses recorded from a real TraceLayer backend.

Nothing in the demo is hand-written. This script:
  1. boots the FastAPI app against a throwaway SQLite database (never your real one);
  2. ingests the seeded synthetic scenario and, if the archive is available, the MIT-licensed OTRF dataset;
  3. runs detection and correlation, generates analyses (deterministic, plus the local LLM if it is running),
     and works the main case as a demo analyst (assignment, triage, notes, pinned evidence, claim reviews);
  4. calls the same GET endpoints the UI uses and writes their JSON responses to a snapshot file
     that the static demo build serves from the browser.

Run:  python -m app.demo.build_snapshot --out ../frontend/public/demo-data/snapshot.json [--otrf-file x.zip] [--llm]
"""

import argparse
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

DEMO_EMAIL, DEMO_PW = "demo.analyst@tracelayer.demo", "Quartz-harbor-snapshot-41"
LEAD_EMAIL, LEAD_PW = "priya@tracelayer.demo", "Velvet-orchard-snapshot-73"


def build(out: Path, otrf_file: str | None, use_llm: bool) -> dict[str, Any]:
    tmp = tempfile.mkdtemp(prefix="tl-demo-")
    os.environ.update(TRACELAYER_DATABASE_URL=f"sqlite:///{tmp}/demo.db", TRACELAYER_BACKGROUND_JOBS="false",
                      TRACELAYER_LLM_MODE="auto" if use_llm else "deterministic", TRACELAYER_DATA_DIR=f"{tmp}/data",
                      TRACELAYER_ARGON2_TIME_COST="1", TRACELAYER_ARGON2_MEMORY_KIB="8192", TRACELAYER_ARGON2_PARALLELISM="1")  # fmt: skip
    from fastapi.testclient import TestClient

    from app.auth.users import create_user
    from app.config import get_settings
    from app.db import session_scope
    from app.main import create_app

    get_settings.cache_clear()
    rec: dict[str, Any] = {}
    with TestClient(create_app()) as c:
        with session_scope() as s:
            create_user(s, email=LEAD_EMAIL, password=LEAD_PW, role="admin", display_name="Priya (SOC lead)")
            create_user(
                s, email=DEMO_EMAIL, password=DEMO_PW, role="analyst", display_name="Dana (demo analyst)", is_demo=True
            )

        def login(email: str, pw: str) -> None:
            r = c.post("/api/auth/login", json={"email": email, "password": pw})
            r.raise_for_status()
            c.headers["X-CSRF-Token"] = r.json()["csrf_token"]

        def ok(r: Any) -> Any:
            assert r.status_code < 300, (r.request.url, r.status_code, r.text[:300])
            return r.json()

        login(LEAD_EMAIL, LEAD_PW)
        ok(
            c.post(
                "/api/synthetic/generate",
                json={"seed": 7, "background_events": 600, "anchor": "fixed", "run_pipeline": True},
            )
        )
        if otrf_file:
            from app.datasets.catalog import DATASETS

            dest = Path(tmp) / "data" / "datasets"
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "otrf-sdwin-200914080546.zip").write_bytes(Path(otrf_file).read_bytes())
            ok(c.post("/api/datasets/otrf-sdwin-200914080546/import"))
            assert DATASETS
        ok(c.post("/api/reports/evaluation"))
        invs = ok(c.get("/api/investigations?view=all"))
        main = next(i for i in invs if "exfiltration" in i["tactics"])
        dana = next(u for u in ok(c.get("/api/users/directory")) if u["display_name"].startswith("Dana"))

        # Analyses: the deterministic analyst always; the real local LLM when requested and available.
        det = ok(c.post(f"/api/investigations/{main['id']}/analyses", json={"engine": "deterministic"}))
        llm = None
        if use_llm:
            # Both pipelines on the same case, so visitors can compare free-form vs grounded generation.
            for engine in ("ollama", "grounded"):
                r = c.post(f"/api/investigations/{main['id']}/analyses", json={"engine": engine})
                llm = (r.json() if r.status_code == 200 else None) or llm
                print(f"LLM analysis ({engine}):", "created" if r.status_code == 200 else f"not available ({r.status_code}: {r.text[:120]})")

        # The lead triages and hands the case to the demo analyst; the deterministic draft gets reviewed.
        v = main["version"]
        main = ok(c.patch(f"/api/investigations/{main['id']}", json={"expected_version": v, "status": "triaged",
                                                                      "reason": "Brute force followed by a successful sign-in from the same address; escalating"}))  # fmt: skip
        main = ok(
            c.patch(
                f"/api/investigations/{main['id']}",
                json={"expected_version": main["version"], "assignee_id": dana["id"]},
            )
        )
        ok(
            c.post(
                f"/api/investigations/{main['id']}/comments",
                json={
                    "kind": "comment",
                    "body": "Dana, this one looks real: the 'successful login' comes from the brute-forcing IP. Please work it and send it to me for review.",
                },
            )
        )
        for claim in det["claims"]:
            if claim["verdict"] in ("unsupported_claim", "contradictory_finding"):
                ok(
                    c.post(
                        f"/api/analyses/{det['id']}/claims/{claim['id']}/review",
                        json={"decision": "reject", "note": "Not supported by the cited events"},
                    )
                )
        ok(
            c.post(
                f"/api/analyses/{det['id']}/review",
                json={
                    "decision": "approve",
                    "note": "Deterministic baseline reviewed; every claim checked against evidence.",
                },
            )
        )

        c.post("/api/auth/logout")
        login(DEMO_EMAIL, DEMO_PW)
        main = ok(c.patch(f"/api/investigations/{main['id']}", json={"expected_version": ok(c.get(f"/api/investigations/{main['id']}"))["version"],
                                                                      "status": "investigating", "reason": "Starting with the sign-in and what followed it"}))  # fmt: skip
        tl = ok(c.get(f"/api/investigations/{main['id']}/timeline"))
        success = next(
            e for e in tl["events"] if e["event_type"] == "auth.login" and e["outcome"] == "success" and e["src_ip"]
        )
        priv = next(e for e in tl["events"] if e["event_type"] == "iam.change")
        for ev, note in (
            (success, "The suspicious sign-in: same IP as the brute force"),
            (priv, "Privilege change: alice added to Domain Admins"),
        ):
            ok(c.post(f"/api/investigations/{main['id']}/evidence", json={"event_id": ev["id"], "note": note}))
        ok(
            c.post(
                f"/api/investigations/{main['id']}/comments",
                json={
                    "kind": "note",
                    "body": "Working hypothesis: credentials for alice were guessed, then used for privilege escalation, lateral movement and exfiltration. db-01 and hr-01 have no process telemetry, so activity there can't be confirmed.",
                },
            )
        )

        # ---- record every response the UI needs, as the demo analyst sees them
        def get(path: str) -> None:
            r = c.get(f"/api{path}")
            if r.status_code == 200:
                rec[path] = r.json()

        for p in ("/auth/me", "/auth/config", "/system/status", "/metrics/overview", "/metrics/performance", "/llm/status",
                  "/datasets", "/detections", "/rules", "/users/directory", "/queues", "/auth/sessions", "/auth/login-history",
                  "/ingest/batches", "/reports?kind=evaluation", "/reports?kind=benchmark", "/pipeline/runs", "/filters",
                  "/investigations?view=all", "/events/facets", "/datasets/coverage", "/auth/activity"):  # fmt: skip
            get(p)
        all_invs = rec["/investigations?view=all"]
        for i in all_invs:
            for sub in ("", "/timeline", "/graph", "/activity", "/comments", "/evidence", "/analyses", "/audit"):
                get(f"/investigations/{i['id']}{sub}")
            get(f"/events/facets?{urlencode({'investigation_id': i['id']})}")
            for fmt in ("md",):  # the JSON export repeats every event; the demo ships md + the real ZIP bundle
                r = c.get(f"/api/investigations/{i['id']}/export?format={fmt}")
                rec[f"/investigations/{i['id']}/export?format={fmt}"] = {"__text__": r.text}
        for d in rec.get("/datasets", []):
            get(f"/datasets/{d['id']}")
        for rep in rec.get("/reports?kind=evaluation", [])[:1]:
            get(f"/reports/{rep['id']}")

        # Events: every event in any investigation scope (plus pins), with its detail and memberships.
        from sqlalchemy import select

        from app.models import DetectionEvent, InvestigationEvent

        with session_scope() as s:
            memb: dict[str, dict[str, Any]] = {}
            for inv_id, ev_id, role in s.execute(
                select(InvestigationEvent.investigation_id, InvestigationEvent.event_id, InvestigationEvent.role)
            ):
                memb.setdefault(ev_id, {"investigations": {}, "detections": []})["investigations"][inv_id] = role
            for det_id, ev_id in s.execute(select(DetectionEvent.detection_id, DetectionEvent.event_id)):
                if ev_id in memb:
                    memb[ev_id]["detections"].append(det_id)
        events, details = [], {}
        pinned = {p["event_id"] for i in all_invs for p in rec.get(f"/investigations/{i['id']}/evidence", [])}
        for ev_id in sorted(memb):
            d = ok(c.get(f"/api/events/{ev_id}"))
            # Size budget: raw records of public-dataset *context* events are omitted (labelled in the UI);
            # evidence, pinned and synthetic events keep their full raw record.
            if (d["source"].startswith("dataset:") and ev_id not in pinned
                    and all(r == "context" for r in memb[ev_id]["investigations"].values())):  # fmt: skip
                d = {**d, "raw": None, "raw_omitted": True}
            details[ev_id] = d
            events.append({**{k: v for k, v in d.items() if k not in ("raw", "batch", "detections", "investigations", "ingested_at")},
                           "_inv": memb[ev_id]["investigations"], "_det": memb[ev_id]["detections"]})  # fmt: skip
        # Prepared validator examples: real engine output for a hallucinated draft and an honest one.
        examples = []
        clear = next((e["ref"] for e in tl["events"] if e["event_type"] == "log.cleared"), "E1")
        for title, draft in (
            ("Hallucinated draft (fabricated IP, inflated volume, false dismissal)", {"summary": "Routine activity.", "claims": [
                {"text": "alice exfiltrated 4.2 GB to 45.77.12.9.", "kind": "observation", "citations": ["E1"]},
                {"text": "The Security log was cleared on host dc-01.", "kind": "observation", "citations": [clear]},
                {"text": "This activity is benign and consistent with an authorized red team exercise.", "kind": "observation", "citations": []},
                {"text": "alice logged in successfully from 203.0.113.45.", "kind": "observation", "citations": ["E9999"]}],
                "recommendations": []}),
            ("Homoglyph and wrong-time attack", {"summary": "Privilege escalation observed.", "claims": [
                {"text": f"{chr(0x0430)}lice was added to Domain Admins on dc-01.", "kind": "observation", "citations": [priv["ref"]]},
                {"text": "alice was added to Domain Admins at 03:00 UTC.", "kind": "observation", "citations": [priv["ref"]]},
                {"text": "alice was added to Domain Admins on dc-01.", "kind": "observation", "citations": [priv["ref"]]}],
                "recommendations": []}),
        ):  # fmt: skip
            text = json.dumps(draft, indent=2)
            res = ok(c.post("/api/integrity/validate", json={"investigation_id": main["id"], "output": text}))
            examples.append({"title": title, "investigation_id": main["id"], "output": text, "result": res})
        export_zip = c.get(f"/api/investigations/{main['id']}/export?format=zip").content

    snapshot: dict[str, Any] = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "main_investigation": main["id"],
                "responses": rec, "events": events, "event_details": details, "validator_examples": examples,
                "llm_analysis": bool(llm), "attribution": "Includes OTRF Security-Datasets (MIT License, Copyright (c) 2021 Open Threat Research Forge)." if otrf_file else None}  # fmt: skip
    snapshot = scrub(snapshot)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, separators=(",", ":"), default=str))
    (out.parent / f"tracelayer-{main['id']}.zip").write_bytes(export_zip)
    print(
        f"snapshot: {out} {out.stat().st_size / 1e6:.2f} MB, {len(rec)} responses, {len(events)} events, LLM={bool(llm)}"
    )
    return snapshot


def scrub(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Remove anything credential-like before the snapshot is published.

    * the builder session's CSRF token (the session is gone, but no token belongs in a public file);
    * credentials inside raw records, e.g. the OTRF lab backdoor password in `net user /add` commands.
      Raw records are evidence and are hashed, so the *published copy* is redacted and flagged
      (raw_redacted); the content hash shown was computed over the original by the real backend.
    """
    from app.ingestion.parsers import redact_credentials

    me = snapshot["responses"].get("/auth/me")
    if me:
        me["csrf_token"] = "demo-transport-does-not-use-csrf"  # noqa: S105 - a placeholder that replaces a real token

    def walk(v: Any) -> tuple[Any, bool]:
        if isinstance(v, str):
            out, changed = redact_credentials(v)
            return out, changed
        if isinstance(v, dict):
            changed = False
            for k in v:
                v[k], c = walk(v[k])
                changed |= c
            return v, changed
        if isinstance(v, list):
            changed = False
            for i, x in enumerate(v):
                v[i], c = walk(x)
                changed |= c
            return v, changed
        return v, False

    for detail in snapshot["event_details"].values():
        if detail.get("raw"):
            detail["raw"], changed = walk(detail["raw"])
            if changed:
                detail["raw_redacted"] = True
    walk(snapshot["responses"])
    walk(snapshot["validator_examples"])
    return snapshot


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../frontend/public/demo-data/snapshot.json")
    ap.add_argument("--otrf-file")
    ap.add_argument("--llm", action="store_true", help="also record a real local-LLM analysis (needs Ollama)")
    ap.add_argument("--scrub-only", action="store_true", help="re-apply scrubbing to an existing snapshot at --out")
    a = ap.parse_args()
    if a.scrub_only:
        p = Path(a.out)
        p.write_text(json.dumps(scrub(json.loads(p.read_text())), separators=(",", ":"), default=str))
        print(f"scrubbed {p}")
        return
    build(Path(a.out), a.otrf_file, a.llm)


if __name__ == "__main__":
    main()
