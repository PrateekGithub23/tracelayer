"""Dataset import safety, the OTRF adapter, and the import/evaluation pipeline (no network needed)."""

import hashlib
import io
import json
import zipfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.datasets import catalog
from app.datasets.archive import ArchiveError, Limits, read_members
from app.datasets.importer import DatasetError, obtain_archive
from app.ingestion.parsers import OtrfWindowsParser, ParseError, redact_credentials


def _zip(members: dict[str, bytes], symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = 0o120777 << 16
            z.writestr(info, "/etc/passwd")
    return buf.getvalue()


# --------------------------------------------------------------------------- archive safety


@pytest.mark.parametrize(
    "name", ["../evil.json", "/abs/evil.json", "a/../../evil.json", "C:/evil.json", "..\\evil.json"]
)
def test_path_traversal_names_are_rejected(name: str) -> None:
    with pytest.raises(ArchiveError, match="unsafe member path"):
        read_members(io.BytesIO(_zip({name: b"{}"})))


def test_symlinks_rejected_and_nothing_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ArchiveError, match="symlink"):
        read_members(io.BytesIO(_zip({"ok.json": b"{}"}, symlink="link.json")))
    assert list(tmp_path.iterdir()) == []  # reading never extracts to disk


def test_zip_bomb_and_limits() -> None:
    bomb = _zip({"bomb.json": b"0" * 5_000_000})  # ~1000x compression
    with pytest.raises(ArchiveError, match="compression ratio"):
        read_members(io.BytesIO(bomb))
    with pytest.raises(ArchiveError, match="expands beyond"):
        read_members(io.BytesIO(_zip({"a.json": b'{"x": 1}\n' * 3000})), Limits(max_member_bytes=1000, max_ratio=1e9))
    with pytest.raises(ArchiveError, match="members"):
        read_members(io.BytesIO(_zip({f"{i}.json": b"{}" for i in range(20)})))
    with pytest.raises(ArchiveError, match="no readable"):
        read_members(io.BytesIO(_zip({"readme.exe": b"MZ"})))
    with pytest.raises(ArchiveError, match="not a valid zip"):
        read_members(io.BytesIO(b"not a zip"))


def test_pinned_hash_mismatch_refuses_import(tmp_path: Path) -> None:
    f = tmp_path / "tampered.zip"
    f.write_bytes(_zip({"x.json": b"{}"}))
    with pytest.raises(DatasetError, match="SHA-256 mismatch"):
        obtain_archive(catalog.DATASETS["otrf-sdwin-200914080546"], str(f))


# --------------------------------------------------------------------------- adapter

BASE = {"@timestamp": "2020-09-14T12:06:02.591Z", "EventTime": "2020-09-14 08:06:02", "Hostname": "WORKSTATION6.theshire.local",
        "RecordNumber": 42, "SourceName": "Microsoft-Windows-Security-Auditing"}  # fmt: skip


def test_otrf_mapping_preserves_identity_and_uses_utc() -> None:
    p = OtrfWindowsParser()
    ev = p.parse({**BASE, "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "User": "THESHIRE\\pgustavo",
                  "Image": "C:\\Windows\\System32\\net.exe", "CommandLine": "net user /add backdoor paw0rd1",
                  "ParentImage": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"})  # fmt: skip
    assert ev.timestamp == datetime(2020, 9, 14, 12, 6, 2, 591000, tzinfo=UTC)  # @timestamp, not local EventTime
    assert (ev.event_type, ev.host, ev.username, ev.process) == ("process.start", "workstation6", "pgustavo", "net.exe")
    assert ev.attributes["parent_process"] == "wmiprvse.exe" and ev.attributes["user_domain"] == "THESHIRE"
    assert ev.attributes["source_event_id"] == "WORKSTATION6.theshire.local/Microsoft-Windows-Sysmon/Operational/42"
    assert ev.attributes["event_time_local"] == "2020-09-14 08:06:02"
    assert ev.command_line == "net user /add backdoor [REDACTED]" and "credential_redacted" in ev.tags
    acct = p.parse(
        {**BASE, "Channel": "Security", "EventID": 4720, "SubjectUserName": "pgustavo", "TargetUserName": "backdoor"}
    )
    assert acct.event_type == "iam.change" and acct.attributes["action"] == "account_create"
    unknown = p.parse(
        {**BASE, "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 13, "Message": "registry set"}
    )
    assert unknown.event_type == "other" and unknown.attributes["event_id"] == 13  # kept, not dropped
    bad_ip = p.parse({**BASE, "Channel": "Security", "EventID": 4624, "TargetUserName": "x", "IpAddress": "not-an-ip"})
    assert bad_ip.src_ip is None  # malformed field in real data does not lose the whole event


def test_otrf_refuses_to_guess_timezone() -> None:
    with pytest.raises(ParseError, match="refusing to guess"):
        OtrfWindowsParser().parse({"EventID": 4624, "Channel": "Security", "EventTime": "2020-09-14 08:06:02"})


@pytest.mark.parametrize(("cmd", "expected"), [
    ("net user bob /domain", "net user bob /domain"),
    ("net localgroup administrators bob /add", "net localgroup administrators bob /add"),
    ("NET1 USER alice S3cr3t! /add", "NET1 USER alice [REDACTED] /add"),
    ("x.exe /password:hunter2", "x.exe /password:[REDACTED]"),
])  # fmt: skip
def test_credential_redaction(cmd: str, expected: str) -> None:
    assert redact_credentials(cmd)[0] == expected


# --------------------------------------------------------------------------- end-to-end import via the API


def _mini_dataset(tmp_path: Path) -> tuple[catalog.Dataset, Path]:
    """A tiny OTRF-shaped archive reproducing the dev scenario's structure (synthetic, for CI)."""

    def rec(n: int, **kw: object) -> dict[str, object]:
        return {**BASE, "RecordNumber": n, "@timestamp": f"2020-09-14T12:06:0{n % 10}.000Z", **kw}

    recs = [
        rec(1, Hostname="WORKSTATION5.theshire.local", Channel="Microsoft-Windows-Sysmon/Operational", EventID=1, User="THESHIRE\\pgustavo",
            Image="C:\\Windows\\System32\\wbem\\WMIC.exe", CommandLine='wmic /node:WORKSTATION6 process call create "net user /add backdoor pw1"'),
        rec(2, Channel="Microsoft-Windows-Sysmon/Operational", EventID=1, User="THESHIRE\\pgustavo", Image="C:\\Windows\\System32\\net.exe",
            CommandLine="net user /add backdoor pw1", ParentImage="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"),
        rec(3, Channel="Security", EventID=4720, SubjectUserName="pgustavo", TargetUserName="backdoor"),
        rec(4, Channel="Microsoft-Windows-Sysmon/Operational", EventID=10, Message="process access"),
    ]  # fmt: skip
    data = _zip({"mini.json": "\n".join(json.dumps(r) for r in recs).encode()})
    f = tmp_path / "mini.zip"
    f.write_bytes(data)
    ds = replace(catalog.DATASETS["otrf-sdwin-200914080546"], id="test-mini", sha256=hashlib.sha256(data).hexdigest())
    return ds, f


def test_import_through_api_and_evaluate(
    admin_client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.config import get_settings

    ds, f = _mini_dataset(tmp_path)
    monkeypatch.setitem(catalog.DATASETS, ds.id, ds)
    monkeypatch.setattr(get_settings(), "data_dir", str(tmp_path / "data"))
    (tmp_path / "data" / "datasets").mkdir(parents=True)
    (tmp_path / "data" / "datasets" / f"{ds.id}.zip").write_bytes(f.read_bytes())
    run = admin_client.post(f"/api/datasets/{ds.id}/import").json()
    assert run["status"] == "succeeded", run
    d = admin_client.get(f"/api/datasets/{ds.id}").json()
    r = d["results"]
    assert d["status"] == "succeeded" and d["event_count"] == 4 and d["license"] == "MIT"
    assert r["technique_recall"] == 1.0 and set(r["techniques_detected"]) == {"T1047", "T1136.001"}
    assert {a["rule_id"] for a in r["alerts"]} >= {"TL-EXEC-002", "TL-PERS-001"}
    assert r["credential_redactions"] == 2 and r["local_time_offsets"] == {"-4h": 4}
    # v3: Sysmon 10 (process access) is now typed. The synthetic mini records omit fields real Sysmon has
    # (process GUIDs, granted access), so they are honestly "partial", with the missing fields named.
    assert r["top_unmapped"] == []
    st = r["coverage"]["statuses"]
    assert st["raw_only"] == 0 and st["full"] + st["partial"] == 4 and st["partial"] >= 1
    assert any(m["field"] == "process.start.process_guid" for m in r["coverage"]["fields_missing"])
    cov = admin_client.get("/api/datasets/coverage").json()
    row = next(x for x in cov["by_source"] if x["source"] == f"dataset:{ds.id}")
    assert row["parser"] == "otrf_windows.v3" and row["full"] + row["partial"] == 4
    assert "Not computed" in r["precision_note"]
    # Re-import is idempotent: same hashes, all duplicates, ledger still verifies.
    assert admin_client.post(f"/api/datasets/{ds.id}/import").json()["status"] == "succeeded"
    assert admin_client.get(f"/api/datasets/{ds.id}").json()["duplicates"] == 4
    assert admin_client.post("/api/integrity/verify").json()["ok"] is True
    sample = zipfile.ZipFile(io.BytesIO(admin_client.get(f"/api/datasets/{ds.id}/sample").content))
    assert "MIT License" in sample.read("LICENSE-NOTICE.txt").decode()
    assert "[REDACTED]" in sample.read("sample.jsonl").decode()  # normalised view is redacted; raw is preserved


def test_v2_events_still_verify_and_renormalize_keeps_evidence(db_url: str, tmp_path: Path) -> None:
    """Adding v3 must not make v2-ingested events look tampered; re-normalising keeps raw and hashes."""
    from app.datasets.renormalize import renormalize
    from app.db import session_scope
    from app.ingestion.pipeline import ingest_records
    from app.integrity.ledger import verify_ledger
    from app.models import Event

    ds, f = _mini_dataset(tmp_path)
    recs = [json.loads(line) for line in zipfile.ZipFile(f).read("mini.json").decode().splitlines()]
    with session_scope() as s:
        ingest_records(s, recs, source="dataset:legacy", parser_name="otrf_windows", options={})  # v2 parser
    with session_scope() as s:
        assert verify_ledger(s)["ok"]
        before = {e.id: (e.content_hash, e.raw, e.batch_id) for e in s.scalars(select(Event))}
        assert {e.event_type for e in s.scalars(select(Event))} >= {"other"}  # v2 left Sysmon 10 raw-only
        res = renormalize(s, "dataset:legacy")
        assert res["changed"] == 4 and "process.access" in res["event_types_after"]
    with session_scope() as s:
        after = {e.id: (e.content_hash, e.raw, e.batch_id) for e in s.scalars(select(Event))}
        assert after == before  # evidence untouched
        assert {e.parser for e in s.scalars(select(Event))} == {"otrf_windows.v3"}
        assert verify_ledger(s)["ok"]  # verifies against the new parser version


def test_v3_adapter_real_world_quirks() -> None:
    from app.ingestion.windows_v3 import OtrfWindowsV3Parser

    p = OtrfWindowsV3Parser()
    # Lower-case channel names occur in real OTRF data; v2 silently left these raw-only.
    ev = p.parse({**BASE, "Channel": "security", "EventID": 5156, "Application": "\\device\\x\\svc.exe",
                  "SourceAddress": "10.0.0.5", "SourcePort": "5000", "DestAddress": "10.0.0.9", "DestPort": "445",
                  "Direction": "%%14593", "Protocol": "6"})  # fmt: skip
    assert ev.event_type == "network.flow" and ev.dst_port == 445 and ev.attributes["norm"]["status"] == "full"
    # PowerShell 800 writes "HostApplication=" (no spaces) while 4103 writes "Host Application = ".
    msg = "Context Information:\r\n\tUserId=THESHIRE\\pgustavo\r\n\tHostApplication=powershell.exe -noP -enc SQBmAA"
    ps = p.parse({**BASE, "Channel": "Windows PowerShell", "EventID": 800, "Message": msg})
    assert ps.event_type == "script.exec" and ps.username == "pgustavo" and ps.command_line.endswith("-enc SQBmAA")
    # Missing fields make an event partial (named), never silently "full"; unknown events stay raw with a reason.
    part = p.parse({**BASE, "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\a\\b.exe"})
    assert part.attributes["norm"]["status"] == "partial" and "command_line" in part.attributes["norm"]["missing"]
    raw = p.parse({**BASE, "Channel": "Security", "EventID": 4999})
    assert raw.event_type == "other" and raw.attributes["norm"]["reason"].startswith("no v3 mapping")
    # Credentials inside parent command lines and registry values are redacted too.
    reg = p.parse({**BASE, "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 13, "Image": "C:\\x.exe",
                   "TargetObject": "HKLM\\Software\\Run\\x", "Details": "net user bob Secret1 /add"})  # fmt: skip
    assert "Secret1" not in json.dumps(reg.columns(), default=str)
