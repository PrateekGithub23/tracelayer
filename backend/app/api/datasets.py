"""Dataset management: catalogue with provenance and licensing, imports, results, and redistributable samples."""

import io
import json
import zipfile
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import jobs
from app.api.deps import require
from app.auth.sessions import Principal
from app.datasets.catalog import DATASETS, OTRF_LICENSE_TEXT
from app.datasets.importer import cache_path, run_import
from app.db import get_db
from app.models import DatasetImport, Event, PipelineRun
from app.schemas import RunOut

router = APIRouter(prefix="/api/datasets", tags=["datasets"])


def _latest(db: Session, dataset_id: str) -> DatasetImport | None:
    return db.scalar(select(DatasetImport).where(DatasetImport.dataset_id == dataset_id)
                     .order_by(DatasetImport.started_at.desc()).limit(1))  # fmt: skip


def _out(db: Session, dataset_id: str) -> dict[str, Any]:
    ds = DATASETS[dataset_id]
    imp = _latest(db, dataset_id)
    return {**ds.public(), "local_file_present": cache_path(ds).exists(),
            "status": imp.status if imp else "not_imported", "import_id": imp.id if imp else None,
            "event_count": imp.accepted if imp else None, "duplicates": imp.duplicates if imp else None,
            "rejected": imp.rejected if imp else None, "imported_at": imp.finished_at if imp else None,
            "imported_by": imp.imported_by if imp else None, "processing_ms": imp.processing_ms if imp else None,
            "archive_sha256": imp.archive_sha256 if imp else None, "batch_ids": imp.batch_ids if imp else [],
            "results": imp.results if imp else None, "error": imp.error if imp else None}  # fmt: skip


@router.get("")
def list_datasets(
    db: Session = Depends(get_db), _: Principal = Depends(require("datasets:read"))
) -> list[dict[str, Any]]:
    return [_out(db, d) for d in DATASETS]


@router.get("/{dataset_id}")
def get_dataset(
    dataset_id: str, db: Session = Depends(get_db), _: Principal = Depends(require("datasets:read"))
) -> dict[str, Any]:
    if dataset_id not in DATASETS:
        raise HTTPException(404, "dataset not found")
    return _out(db, dataset_id)


@router.post("/{dataset_id}/import", response_model=RunOut)
def import_dataset(dataset_id: str, db: Session = Depends(get_db),
                   p: Principal = Depends(require("datasets:manage"))) -> PipelineRun:  # fmt: skip
    if dataset_id not in DATASETS:
        raise HTTPException(404, "dataset not found")
    if db.scalar(
        select(DatasetImport.id).where(DatasetImport.dataset_id == dataset_id, DatasetImport.status == "running")
    ):
        raise HTTPException(409, "an import of this dataset is already running")
    actor = p.actor

    def job(s: Session, _rid: str) -> dict[str, Any]:
        imp = run_import(s, dataset_id, actor=actor)
        if imp.status != "succeeded":
            raise RuntimeError(f"import failed (see dataset page): {imp.error}")
        return {"import_id": imp.id, "accepted": imp.accepted, "duplicates": imp.duplicates}

    run_id = jobs.submit("dataset_import", job, {"dataset_id": dataset_id})
    db.expire_all()
    return db.get(PipelineRun, run_id)  # type: ignore[return-value]


@router.get("/{dataset_id}/sample")
def sample(
    dataset_id: str, db: Session = Depends(get_db), _: Principal = Depends(require("datasets:read"))
) -> Response:
    """First 200 imported records (raw + normalised) with the licence notice. Only for redistributable datasets."""
    ds = DATASETS.get(dataset_id)
    if not ds:
        raise HTTPException(404, "dataset not found")
    if not ds.redistribution.lower().startswith(("mit", "apache", "cc-by", "public domain")):
        raise HTTPException(403, "this dataset's licence does not permit redistribution")
    rows = list(
        db.scalars(
            select(Event).where(Event.source == f"dataset:{ds.id}").order_by(Event.timestamp, Event.id).limit(200)
        )
    )
    if not rows:
        raise HTTPException(404, "import the dataset first")
    lines = [json.dumps({"event_id": e.id, "content_hash": e.content_hash, "normalised": {
        "timestamp": e.timestamp.isoformat(), "event_type": e.event_type, "host": e.host, "username": e.username,
        "src_ip": e.src_ip, "dst_ip": e.dst_ip, "process": e.process, "command_line": e.command_line,
        "attributes": e.attributes, "tags": e.tags}, "raw": e.raw}, default=str) for e in rows]  # fmt: skip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("sample.jsonl", "\n".join(lines) + "\n")
        z.writestr(
            "LICENSE-NOTICE.txt",
            f"{ds.attribution}\nSource: {ds.url}\nSHA-256 of source archive: {ds.sha256}\n"
            f"Modified: TraceLayer added normalised fields alongside each unmodified raw record.\n\n{OTRF_LICENSE_TEXT}\n",
        )
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{ds.id}-sample.zip"'})  # fmt: skip
