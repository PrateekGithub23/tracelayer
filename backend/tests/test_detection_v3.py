"""v3 rules and pipeline edge cases: timezones, late-arriving events, duplicates, missing fields."""

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.base import EventView
from app.detection.engine import run_detection
from app.detection.rules import LsassMemoryAccess, RegistryRunKey
from app.ingestion.pipeline import ingest_records
from app.models import Detection

T0 = datetime(2026, 11, 3, 10, 0, tzinfo=UTC)


def ev(etype: str, minute: int = 0, **kw: Any) -> EventView:
    base: dict[str, Any] = dict(id=f"evt_{etype}_{minute}_{kw.get('process', '')}", timestamp=T0 + timedelta(minutes=minute),
                                event_type=etype, host="ws5", username=None, src_ip=None, dst_ip=None, dst_port=None,
                                process=None, command_line=None, outcome="success", bytes_out=None, country=None,
                                attributes={}, tags=[])  # fmt: skip
    base.update(kw)
    return EventView(**base)


def test_lsass_rule_masks_and_benign_accessors() -> None:
    r = LsassMemoryAccess()
    hits = r.evaluate([
        ev("process.access", 0, process="powershell.exe", attributes={"target_process": "lsass.exe", "granted_access": "0x1010"}),
        ev("process.access", 1, process="procdump.exe", attributes={"target_process": "LSASS.EXE", "granted_access": "0x1FFFFF"}),
        ev("process.access", 2, process="wininit.exe", attributes={"target_process": "lsass.exe", "granted_access": "0x1fffff"}),  # benign
        ev("process.access", 3, process="svchost.exe", attributes={"target_process": "lsass.exe", "granted_access": "0x1000"}),  # no VM_READ
        ev("process.access", 4, process="evil.exe", attributes={"target_process": "notepad.exe", "granted_access": "0x1010"}),
    ])  # fmt: skip
    assert sorted(h.summary.split(" ")[0] for h in hits) == ["powershell.exe", "procdump.exe"]
    assert all(h.technique == "T1003.001" and h.severity == "critical" for h in hits)


def test_run_key_rule_exact_paths_only() -> None:
    r = RegistryRunKey()

    def mk(key: str, eid: int = 13) -> EventView:
        return ev("registry.change", process="powershell.exe", attributes={"registry_key": key, "event_id": eid})

    hits = r.evaluate([
        mk(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater"),
        mk(r"HKU\S-1-5-21\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\x"),
        mk(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Runtime\x"),  # look-alike key
        mk(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater", eid=12),  # key create, not a value set
    ])  # fmt: skip
    assert len(hits) == 2 and {h.summary.rsplit("'", 2)[1] for h in hits} == {"Updater", "x"}


def _sysmon_lsass(ts: str, rec: int, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"@timestamp": ts, "EventTime": "2026-11-03 05:00:00", "Hostname": "WS5.lab.local", "RecordNumber": rec,
            "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 10, "SourceImage": "C:\\t\\dump.exe",
            "SourceProcessGUID": "{a}", "SourceProcessId": "1", "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "TargetProcessGUID": "{b}", "GrantedAccess": "0x1010", **(extra or {})}  # fmt: skip


def test_timezone_late_arrival_duplicates_and_missing_fields(db: Session) -> None:
    # 1. Timezones: the same instant written as Z and as +02:00 is one moment; local EventTime is ignored.
    a = _sysmon_lsass("2026-11-03T10:00:00Z", 1)
    b = _sysmon_lsass("2026-11-03T12:05:00+02:00", 2)  # = 10:05 UTC
    r1 = ingest_records(db, [a, b], source="t", parser_name="otrf_windows.v3", options={})
    assert r1.accepted == 2
    run_detection(db)
    db.commit()
    dets = list(db.scalars(select(Detection).where(Detection.rule_id == "TL-CRED-001")))
    assert len(dets) == 1 and dets[0].evidence_count == 2  # one burst: 5 minutes apart in UTC
    # 2. Duplicates: re-sending the same records adds nothing and changes no detection.
    r2 = ingest_records(db, [a, b], source="t", parser_name="otrf_windows.v3", options={})
    assert r2.accepted == 0 and r2.duplicates == 2
    # 3. Late arrival: an earlier event arriving afterwards merges into the existing detection (idempotent ids).
    late = _sysmon_lsass("2026-11-03T09:58:00Z", 3)
    ingest_records(db, [late], source="t", parser_name="otrf_windows.v3", options={})
    run_detection(db)
    db.commit()
    dets = list(db.scalars(select(Detection).where(Detection.rule_id == "TL-CRED-001")))
    assert sum(d.evidence_count for d in dets) == 3
    # 4. Missing fields: no GrantedAccess -> partial normalisation, and the rule does not guess.
    nomask = _sysmon_lsass("2026-11-03T15:00:00Z", 4, {"GrantedAccess": None})
    ingest_records(db, [nomask], source="t", parser_name="otrf_windows.v3", options={})
    run_detection(db)
    db.commit()
    dets = list(db.scalars(select(Detection).where(Detection.rule_id == "TL-CRED-001")))
    assert sum(d.evidence_count for d in dets) == 3
