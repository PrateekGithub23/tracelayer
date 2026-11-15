"""
Evidence bundle export.

A bundle is a ZIP containing:
  investigation.json  - investigation, detections, analyses with claim verdicts, audit trail
  events.jsonl        - every in-scope event with its raw record and content hash
  events.csv          - analyst-friendly flat view
  report.md           - human-readable report (verified facts separated from hypotheses)
  manifest.json       - SHA-256 of every file + the ledger chain head at export time

The manifest makes the bundle independently checkable: a recipient can recompute
each event's hash from its raw record (`sha256(source + "\\n" + canonical_json(raw))`)
and each file's hash, without access to TraceLayer.
"""

import csv
import io
import json
import zipfile
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.integrity.ledger import verify_event
from app.integrity.provenance import canonical_json, sha256_hex
from app.integrity.validator import UNSAFE
from app.models import (
    AIAnalysis,
    AuditEntry,
    CaseComment,
    CaseEvidence,
    Detection,
    Event,
    IngestBatch,
    Investigation,
    InvestigationEvent,
    User,
)

CSV_FIELDS = ["id", "timestamp", "event_type", "outcome", "host", "username", "src_ip", "dst_ip", "dst_port",
              "process", "command_line", "bytes_out", "country", "role", "content_hash", "batch_id"]  # fmt: skip


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def collect(db: Session, inv: Investigation) -> dict[str, Any]:
    rows = db.execute(
        select(Event, InvestigationEvent.role).join(InvestigationEvent, InvestigationEvent.event_id == Event.id)
        .where(InvestigationEvent.investigation_id == inv.id).order_by(Event.timestamp)
    ).all()  # fmt: skip
    events = []
    tampered = 0
    for ev, role in rows:
        check = verify_event(ev)
        tampered += not check.ok
        events.append({
            "id": ev.id, "timestamp": ev.timestamp.isoformat(), "event_type": ev.event_type, "outcome": ev.outcome,
            "host": ev.host, "username": ev.username, "src_ip": ev.src_ip, "dst_ip": ev.dst_ip,
            "dst_port": ev.dst_port, "process": ev.process, "command_line": ev.command_line,
            "bytes_out": ev.bytes_out, "country": ev.country, "attributes": ev.attributes, "tags": ev.tags,
            "role": role, "source": ev.source, "parser": ev.parser, "batch_id": ev.batch_id,
            "content_hash": ev.content_hash, "raw": ev.raw, "integrity_ok": check.ok,
        })  # fmt: skip
    dets = db.scalars(select(Detection).where(Detection.investigation_id == inv.id).order_by(Detection.first_seen))
    analyses = db.scalars(select(AIAnalysis).where(AIAnalysis.investigation_id == inv.id)
                          .order_by(AIAnalysis.created_at))  # fmt: skip
    analysis_ids = []
    analysis_out = []
    for a in analyses:
        analysis_ids.append(a.id)
        analysis_out.append({
            "id": a.id, "engine": a.engine, "model": a.model, "status": a.status, "summary": a.summary,
            "integrity": a.integrity, "created_at": _iso(a.created_at), "reviewed_by": a.reviewed_by,
            "reviewed_at": _iso(a.reviewed_at), "review_note": a.review_note,
            "evidence_pack_sha256": a.evidence_pack_sha256, "fallback_reason": a.fallback_reason,
            "claims": [{"text": c.text, "declared_kind": c.declared_kind, "verdict": c.verdict, "reasons": c.reasons,
                        "citations": c.citations, "review_status": c.review_status,
                        "review_note": c.review_note} for c in a.claims],
        })  # fmt: skip
    audit_rows = db.scalars(select(AuditEntry).where(AuditEntry.target_id.in_([inv.id, *analysis_ids]))
                            .order_by(AuditEntry.id))  # fmt: skip
    head = db.execute(select(IngestBatch.seq, IngestBatch.chain_hash).order_by(IngestBatch.seq.desc()).limit(1)).first()
    comments = list(db.scalars(select(CaseComment).where(CaseComment.investigation_id == inv.id,
                                                         CaseComment.deleted_at.is_(None)).order_by(CaseComment.created_at)))  # fmt: skip
    pins = list(db.scalars(select(CaseEvidence).where(CaseEvidence.investigation_id == inv.id)))
    uids = {inv.assignee_id, inv.reviewer_id, *(c.author_id for c in comments), *(p.added_by for p in pins)}
    names = {u.id: u.display_name for u in db.scalars(select(User).where(User.id.in_([x for x in uids if x])))}
    return {
        "investigation": {
            "id": inv.id,
            "title": inv.title,
            "status": inv.status,
            "severity": inv.severity,
            "score": inv.score,
            "score_breakdown": inv.score_breakdown,
            "first_seen": _iso(inv.first_seen),
            "last_seen": _iso(inv.last_seen),
            "entities": inv.entities,
            "tactics": inv.tactics,
            "priority": inv.priority,
            "assignee": names.get(inv.assignee_id or ""),
            "reviewer": names.get(inv.reviewer_id or ""),
            "legacy_assignee": inv.legacy_assignee,
            "resolution": inv.resolution,
            "resolved_at": _iso(inv.resolved_at) if inv.resolved_at else None,
            "closed_at": _iso(inv.closed_at) if inv.closed_at else None,
            "reopen_count": inv.reopen_count,
            "version": inv.version,
            "approved_analysis_id": inv.approved_analysis_id,
        },  # fmt: skip
        "notes": [
            {
                "id": c.id,
                "kind": c.kind,
                "author": names.get(c.author_id),
                "created_at": _iso(c.created_at),
                "edited_at": _iso(c.edited_at) if c.edited_at else None,
                "body": c.body,
            }
            for c in comments
        ],
        "pinned_evidence": [
            {
                "event_id": p.event_id,
                "note": p.note,
                "added_by": names.get(p.added_by),
                "created_at": _iso(p.created_at),
            }
            for p in pins
        ],
        "detections": [
            {
                "id": d.id,
                "rule_id": d.rule_id,
                "rule_name": d.rule_name,
                "severity": d.severity,
                "confidence": d.confidence,
                "tactic": d.tactic,
                "technique": d.technique,
                "first_seen": _iso(d.first_seen),
                "last_seen": _iso(d.last_seen),
                "summary": d.summary,
                "entities": d.entities,
            }
            for d in dets
        ],  # fmt: skip
        "analyses": analysis_out,
        "audit": [
            {
                "id": e.id,
                "timestamp": _iso(e.timestamp),
                "actor": e.actor,
                "action": e.action,
                "target_type": e.target_type,
                "target_id": e.target_id,
                "details": e.details,
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
            }
            for e in audit_rows
        ],  # fmt: skip
        "events": events,
        "ledger_head": {"seq": head.seq, "chain_hash": head.chain_hash} if head else None,
        "events_failing_integrity": tampered,
    }


_MD_SPECIAL = str.maketrans({c: "\\" + c for c in "\\`*_[]<>|#!"} | {"\n": " ", "\r": " "})


def md(text: Any) -> str:
    """Escape untrusted text (log fields, model output, analyst notes) for Markdown.

    Prevents table breakage and, more importantly, live links/images/HTML such as
    `[click](javascript:...)` or `<img src=x onerror=...>` appearing in a report rendered by another tool.
    """
    return str(text).translate(_MD_SPECIAL)


def render_markdown(data: dict[str, Any]) -> str:
    inv = data["investigation"]
    out = [f"# {md(inv['title'])}", "",
           f"- **Investigation:** `{inv['id']}`  ",
           f"- **Status:** {inv['status']}" + (f" ({inv['resolution']})" if inv.get("resolution") else "")
           + f" · **Priority:** {inv.get('priority', '-')} · **Assignee:** {md(inv.get('assignee') or 'unassigned')}  ",
           f"- **Severity:** {inv['severity']} · **Score:** {inv['score']}  ",
           f"- **Window:** {inv['first_seen']} → {inv['last_seen']}  ",
           f"- **Tactics:** {', '.join(inv['tactics'])}  ",
           f"- **Events in scope:** {len(data['events'])} ({data['events_failing_integrity']} failing integrity checks)",
           "", "## Detections", "", "| Severity | Rule | Technique | First seen | Summary |", "|---|---|---|---|---|"]  # fmt: skip
    for d in data["detections"]:
        out.append(
            f"| {d['severity']} | {md(d['rule_name'])} | {d['technique']} | {d['first_seen']} | {md(d['summary'])} |"
        )
    approved = next((a for a in data["analyses"] if a["id"] == inv.get("approved_analysis_id")), None)
    analysis = approved or (data["analyses"][-1] if data["analyses"] else None)
    if analysis:
        state = "APPROVED" if approved else f"NOT APPROVED ({analysis['status']})"
        out += ["", f"## Analysis — {state}", "",
                f"Generated by `{analysis['engine']}` / `{analysis['model']}` · integrity score "
                f"{analysis['integrity'].get('integrity_score')}", "", md(analysis["summary"]), ""]  # fmt: skip
        sections = [
            ("Verified observations", {"verified_observation"}),
            ("Heuristic correlations", {"heuristic_correlation"}),
            ("Hypotheses (unverified)", {"ai_hypothesis"}),
            ("Missing evidence", {"missing_evidence"}),
            ("Rejected / unsafe claims", UNSAFE),
        ]
        for title, verdicts in sections:
            claims = [c for c in analysis["claims"] if c["verdict"] in verdicts]
            if not claims:
                continue
            out += [f"### {title}", ""]
            for c in claims:
                cites = ", ".join(f"`{x}`" for x in c["citations"][:8])
                more = f" (+{len(c['citations']) - 8} more)" if len(c["citations"]) > 8 else ""
                review = f" — analyst: **{c['review_status']}**" if c["review_status"] != "pending" else ""
                out.append(f"- {md(c['text'])}{review}  ")
                out.append(f"  _Evidence:_ {cites or 'none'}{more}" + (f"  _Why:_ {md('; '.join(c['reasons']))}"
                           if c["verdict"] in UNSAFE else ""))  # fmt: skip
            out.append("")
    if data.get("notes"):
        out += ["## Analyst notes and comments", ""]
        out += [
            f"- **{md(n['author'] or '?')}** ({n['kind']}, {n['created_at']}): {md(n['body'])}" for n in data["notes"]
        ]
        out.append("")
    if data.get("pinned_evidence"):
        out += ["## Pinned evidence", ""]
        out += [
            f"- `{p['event_id']}`: {md(p['note'] or '')} (pinned by {md(p['added_by'] or '?')})"
            for p in data["pinned_evidence"]
        ]
        out.append("")
    out += ["## Provenance", "",
            f"Ledger head at export: seq {data['ledger_head']['seq'] if data['ledger_head'] else '-'}, "
            f"`{data['ledger_head']['chain_hash'] if data['ledger_head'] else '-'}`", "",
            "Each event hash = SHA-256(source + \"\\n\" + canonical JSON of raw record). See manifest.json.", ""]  # fmt: skip
    return "\n".join(out)


def render_csv(data: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for e in data["events"]:
        # Neutralise spreadsheet formula injection (CSV injection) from attacker-controlled fields.
        w.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@\t\r" else v) for k, v in e.items()})
    return buf.getvalue()


def build_bundle(db: Session, inv: Investigation) -> tuple[bytes, dict[str, Any]]:
    data = collect(db, inv)
    files = {
        "investigation.json": json.dumps({k: v for k, v in data.items() if k != "events"}, indent=2, default=str),
        "events.jsonl": "\n".join(canonical_json(e) for e in data["events"]) + "\n",
        "events.csv": render_csv(data),
        "report.md": render_markdown(data),
    }
    manifest = {
        "format": "tracelayer-evidence-bundle/1",
        "generator": f"TraceLayer {__version__}",
        "exported_at": datetime.now(UTC).isoformat(),
        "investigation_id": inv.id,
        "ledger_head": data["ledger_head"],
        "event_count": len(data["events"]),
        "events_failing_integrity": data["events_failing_integrity"],
        "files": {name: sha256_hex(content) for name, content in files.items()},
    }
    manifest["bundle_sha256"] = sha256_hex(canonical_json(manifest["files"]))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
    return buf.getvalue(), manifest
