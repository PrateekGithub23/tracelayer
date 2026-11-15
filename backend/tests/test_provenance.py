"""Ingestion, deduplication, the hash-chained ledger, and tamper detection."""

import threading

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.db import session_factory
from app.ingestion.pipeline import ingest_records
from app.integrity.ledger import verify_ledger
from app.integrity.provenance import canonical_json, merkle_root, record_hash
from app.models import Event, IngestBatch

REC = {"timestamp": "2026-11-03T10:00:00Z", "event_type": "auth.login", "outcome": "failure", "user": "a"}


def test_record_hash_is_key_order_independent_and_source_bound() -> None:
    a = {"x": 1, "y": [1, 2], "z": "é"}
    b = {"z": "é", "y": [1, 2], "x": 1}
    assert canonical_json(a) == canonical_json(b)
    assert record_hash("s1", a) == record_hash("s1", b)
    assert record_hash("s1", a) != record_hash("s2", a)


def test_merkle_root_is_set_commitment() -> None:
    h = [record_hash("s", {"i": i}) for i in range(5)]
    assert merkle_root(h) == merkle_root(list(reversed(h)))
    assert merkle_root(h) != merkle_root(h[:4])


def test_dedup_within_and_across_batches(db: Session) -> None:
    other = {**REC, "user": "b"}
    r1 = ingest_records(db, [REC, REC, other, {"bad": True}], source="t", parser_name="native")
    assert (r1.accepted, r1.duplicates, r1.rejected) == (2, 1, 1)
    assert r1.errors[0]["index"] == 3
    r2 = ingest_records(db, [REC, other], source="t", parser_name="native")
    assert (r2.accepted, r2.duplicates) == (0, 2)
    assert db.query(Event).count() == 2
    # Same record from a different collector is a different observation.
    assert ingest_records(db, [REC], source="t2", parser_name="native").accepted == 1


def test_ledger_chain_links_batches(db: Session) -> None:
    for i in range(3):
        ingest_records(db, [{**REC, "user": f"u{i}"}], source="t", parser_name="native")
    batches = list(db.scalars(select(IngestBatch).order_by(IngestBatch.seq)))
    assert [b.seq for b in batches] == [1, 2, 3]
    assert batches[1].prev_chain_hash == batches[0].chain_hash
    assert verify_ledger(db)["ok"]


def _seed(db: Session) -> None:
    ingest_records(db, [{**REC, "user": f"u{i}"} for i in range(10)], source="t", parser_name="native")
    ingest_records(db, [{**REC, "user": f"v{i}"} for i in range(10)], source="t", parser_name="native")


def test_detects_modified_raw_record(db: Session) -> None:
    _seed(db)
    ev = db.scalars(select(Event)).first()
    db.execute(update(Event).where(Event.id == ev.id).values(raw={**ev.raw, "user": "attacker"}))
    db.commit()
    report = verify_ledger(db)
    assert not report["ok"]
    assert any(i["kind"] == "event_tampered" and i["target"] == ev.id for i in report["issues"])


def test_detects_modified_normalised_column(db: Session) -> None:
    _seed(db)
    ev = db.scalars(select(Event)).first()
    db.execute(update(Event).where(Event.id == ev.id).values(username="someone-else"))
    db.commit()
    issues = verify_ledger(db)["issues"]
    assert any("username" in i["detail"] for i in issues)


def test_detects_deleted_event_and_edited_batch(db: Session) -> None:
    _seed(db)
    ev = db.scalars(select(Event)).first()
    db.execute(delete(Event).where(Event.id == ev.id))
    db.execute(update(IngestBatch).where(IngestBatch.seq == 2).values(source="rewritten"))
    db.commit()
    kinds = {i["kind"] for i in verify_ledger(db)["issues"]}
    assert {"merkle_mismatch", "count_mismatch", "chain_hash_mismatch"} <= kinds


def test_concurrent_ingestion_keeps_ledger_consistent(db_url: str) -> None:
    """Many threads ingesting overlapping records: no duplicate events, unbroken chain."""
    errors: list[Exception] = []

    def worker(n: int) -> None:
        s = session_factory()()
        try:
            recs = [{**REC, "user": f"u{(n + i) % 15}"} for i in range(10)]
            ingest_records(s, recs, source="t", parser_name="native")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            s.close()

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    s = session_factory()()
    assert s.query(Event).count() == 15
    report = verify_ledger(s)
    assert report["ok"], report["issues"]
    assert report["batches_checked"] == 8
    s.close()
