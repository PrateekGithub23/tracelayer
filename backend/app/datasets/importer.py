"""
Import a catalogued public dataset through the normal ingestion pipeline, then evaluate the detection
rules against it.

Pipeline: obtain archive (cached file or pinned download) -> verify SHA-256 -> safe in-memory read ->
JSON lines -> ingest_records (same hashing, dedup and ledger chaining as any other source) ->
detection + correlation -> evaluation results stored on the DatasetImport row.

The evaluation reports only what the labels support (see docs/REAL_WORLD_DATA_EVALUATION.md):
technique-level recall, every alert with its evidence, cross-source correlations, and what the
normalised schema could not represent. It never reports false-positive rates, because these datasets
have no benign-only baseline.
"""

import hashlib
import io
import json
import logging
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.datasets.archive import read_members
from app.datasets.catalog import DATASETS, Dataset
from app.datasets.coverage import coverage
from app.ids import new_id
from app.ingestion.pipeline import ingest_records
from app.models import DatasetImport, Detection, DetectionEvent, Event, Investigation, InvestigationEvent, utcnow

log = logging.getLogger("tracelayer.datasets")
CHUNK = 5000


class DatasetError(RuntimeError):
    pass


def cache_path(ds: Dataset) -> Path:
    return Path(get_settings().data_dir) / "datasets" / f"{ds.id}.zip"


def obtain_archive(ds: Dataset, local_file: str | None = None) -> tuple[bytes, float]:
    """Return verified archive bytes and download time (0 if cached). Never trusts unverified bytes."""
    t0 = time.perf_counter()
    path = Path(local_file) if local_file else cache_path(ds)
    if path.exists():
        data = path.read_bytes()[: ds.max_bytes + 1]
        downloaded = 0.0
    else:
        if not get_settings().allow_dataset_download:
            raise DatasetError(f"{ds.id}: not cached at {path} and downloads are disabled")
        with httpx.stream("GET", ds.url, timeout=60, follow_redirects=False) as r:
            if r.status_code != 200:
                raise DatasetError(f"download failed: HTTP {r.status_code}")
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > ds.max_bytes:
                    raise DatasetError("download exceeds the catalogued size limit")
            data = bytes(buf)
        downloaded = (time.perf_counter() - t0) * 1000
    if len(data) > ds.max_bytes:
        raise DatasetError("archive exceeds the catalogued size limit")
    digest = hashlib.sha256(data).hexdigest()
    if digest != ds.sha256:
        raise DatasetError(f"SHA-256 mismatch: expected {ds.sha256}, got {digest}. Refusing to import.")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".part")
        tmp.write_bytes(data)
        tmp.replace(path)  # atomic: a crashed download never leaves a half-written cache entry
    return data, downloaded


def _records(data: bytes) -> tuple[list[Any], int]:
    records, bad = [], 0
    for _name, content in sorted(read_members(io.BytesIO(data)).items()):
        for line in content.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    return records, bad


def _technique_match(detected: str, labelled: str) -> bool:
    """T1136 matches T1136.001 and vice versa (parent/sub-technique)."""
    return detected == labelled or detected.split(".")[0] == labelled.split(".")[0]


def evaluate(db: Session, ds: Dataset) -> dict[str, Any]:
    source = f"dataset:{ds.id}"
    ds_events = select(Event.id).where(Event.source == source)
    total = db.scalar(select(func.count()).select_from(Event).where(Event.source == source)) or 0
    types: dict[str, int] = {t: n for t, n in db.execute(select(Event.event_type, func.count()).where(Event.source == source)
                            .group_by(Event.event_type))}  # fmt: skip
    det_ids = set(db.scalars(select(DetectionEvent.detection_id).where(DetectionEvent.event_id.in_(ds_events))))
    dets = list(db.scalars(select(Detection).where(Detection.id.in_(det_ids)).order_by(Detection.first_seen)))
    alerts: list[dict[str, Any]] = []
    for d in dets:
        srcs: list[str] = sorted(set(db.scalars(select(Event.source).join(DetectionEvent, DetectionEvent.event_id == Event.id)
                                     .where(DetectionEvent.detection_id == d.id))))  # fmt: skip
        alerts.append({"id": d.id, "rule_id": d.rule_id, "rule_name": d.rule_name, "technique": d.technique,
                       "tactic": d.tactic, "severity": d.severity, "evidence_count": d.evidence_count,
                       "summary": d.summary, "first_seen": d.first_seen.isoformat(), "sources": srcs,
                       "matches_label": any(_technique_match(d.technique, t) for t in ds.techniques)})  # fmt: skip
    detected = sorted({t for t in ds.techniques if any(_technique_match(a["technique"], t) for a in alerts)})
    inv_ids = set(
        db.scalars(select(InvestigationEvent.investigation_id).where(InvestigationEvent.event_id.in_(ds_events)))
    )
    correlations = []
    for inv in db.scalars(select(Investigation).where(Investigation.id.in_(inv_ids))):
        q = (select(Event.source, func.count()).join(InvestigationEvent, InvestigationEvent.event_id == Event.id)
             .where(InvestigationEvent.investigation_id == inv.id).group_by(Event.source))  # fmt: skip
        by_src: dict[str, int] = {k: n for k, n in db.execute(q)}
        correlations.append({"investigation_id": inv.id, "title": inv.title, "severity": inv.severity,
                             "sources": by_src, "cross_source": len(by_src) > 1})  # fmt: skip
    # Schema loss: which original (channel, event id) pairs had no normalised mapping.
    other: Counter[str] = Counter()
    redacted = injected = 0
    offsets: Counter[str] = Counter()
    for etype, attrs, tags, ts in db.execute(
        select(Event.event_type, Event.attributes, Event.tags, Event.timestamp).where(Event.source == source)
    ):
        redacted += "credential_redacted" in tags
        injected += "llm_injection_suspected" in tags
        if etype == "other":
            other[f"{attrs.get('channel')} {attrs.get('event_id')}"] += 1
        local = attrs.get("event_time_local")
        if local:
            try:
                delta = (datetime.fromisoformat(local) - ts.replace(tzinfo=None)).total_seconds() / 3600
                offsets[f"{delta:+.0f}h"] += 1
            except ValueError:
                offsets["unparseable"] += 1
    labelled = list(ds.techniques)
    return {
        "events": total,
        "event_types": types,
        "unmapped_share": round(types.get("other", 0) / total, 4) if total else None,
        "top_unmapped": [{"source": k, "count": v} for k, v in other.most_common(15)],
        "credential_redactions": redacted,
        "injection_tagged": injected,
        "local_time_offsets": dict(offsets),
        "techniques_labelled": labelled,
        "techniques_detected": detected,
        "technique_recall": round(len(detected) / len(labelled), 3) if labelled else None,
        "techniques_missed": [t for t in labelled if t not in detected],
        "alerts": alerts,
        "alert_count": len(alerts),
        "alerts_matching_labels": sum(a["matches_label"] for a in alerts),
        "correlations": correlations,
        "cross_source_correlations": sum(c["cross_source"] for c in correlations),
        "coverage": {k: v for k, v in coverage(db, source).items() if k != "by_source"},
        "parser": ds.parser,
        "precision_note": (
            "Not computed: the dataset has technique-level labels only and no benign baseline, "
            "so alert-level precision and false-positive rates would be invented."
        ),
    }


def run_import(db: Session, dataset_id: str, *, actor: str = "system", local_file: str | None = None) -> DatasetImport:
    from app.jobs import detect_and_correlate

    ds = DATASETS.get(dataset_id)
    if not ds:
        raise DatasetError(f"unknown dataset {dataset_id!r}")
    imp = DatasetImport(id=new_id("dsi"), dataset_id=ds.id, status="running", imported_by=actor)
    db.add(imp)
    db.commit()
    t0 = time.perf_counter()
    try:
        data, download_ms = obtain_archive(ds, local_file)
        imp.archive_sha256 = hashlib.sha256(data).hexdigest()
        t_parse = time.perf_counter()
        records, bad_lines = _records(data)
        imp.records = len(records) + bad_lines
        batch_ids = []
        for i in range(0, len(records), CHUNK):
            r = ingest_records(db, records[i : i + CHUNK], source=f"dataset:{ds.id}", parser_name=ds.parser, options={})
            batch_ids.append(r.batch_id)
            imp.accepted += r.accepted
            imp.duplicates += r.duplicates
            imp.rejected += r.rejected
        imp.rejected += bad_lines
        ingest_ms = (time.perf_counter() - t_parse) * 1000
        db.commit()
        t_det = time.perf_counter()
        stats = detect_and_correlate(db, f"dataset-{imp.id}")
        db.commit()
        detect_ms = (time.perf_counter() - t_det) * 1000
        results = evaluate(db, ds)
        results["timings_ms"] = {"download": round(download_ms, 1), "parse_and_ingest": round(ingest_ms, 1),
                                 "detect_and_correlate": round(detect_ms, 1),
                                 "events_per_sec": round(imp.accepted / (ingest_ms / 1000), 1) if ingest_ms and imp.accepted else None}  # fmt: skip
        results["pipeline"] = {"detections_created": stats["detection"].get("created"),
                               "investigations_created": stats["correlation"].get("investigations_created")}  # fmt: skip
        imp.results, imp.batch_ids, imp.status = results, batch_ids, "succeeded"
    except Exception as exc:  # noqa: BLE001 - recorded on the import row; details in the server log
        db.rollback()
        log.exception("dataset import %s failed", imp.id)
        imp = db.get(DatasetImport, imp.id) or imp
        imp.status, imp.error = "failed", f"{type(exc).__name__}: {str(exc)[:300]}"
    imp.processing_ms = round((time.perf_counter() - t0) * 1000, 1)
    imp.finished_at = utcnow()
    audit.record(db, actor=actor, action=f"dataset.import_{imp.status}", target_type="dataset", target_id=ds.id,
                 details={"import_id": imp.id, "accepted": imp.accepted, "duplicates": imp.duplicates,
                          "rejected": imp.rejected, "sha256": imp.archive_sha256, "error": imp.error})  # fmt: skip
    db.commit()
    return imp
