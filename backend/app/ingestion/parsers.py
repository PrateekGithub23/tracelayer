"""
Log parsers.

Every parser turns one input record into:
  1. a `raw` dict  - exactly what we will store and hash (the provenance anchor), and
  2. a NormalizedEvent - the common schema used by detection and correlation.

Parsing is a *pure function of raw*. That property is what lets the integrity
verifier re-run the parser later and prove the normalised columns were not
edited after ingestion.

Supported formats:
  native  - TraceLayer JSON events
  sshd    - OpenSSH syslog lines (auth.log)
  winsec  - Windows Security event log records exported as JSON
"""

import ipaddress
import re
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from typing import Any, Protocol

EVENT_TYPES = {
    "auth.login",
    "process.start",
    "network.flow",
    "iam.change",
    "dns.query",
    "file.access",
    "log.cleared",
    "other",
}
OUTCOMES = {"success", "failure", "unknown"}

MAX_STR = 1024
MAX_CMD = 8192

# Text inside telemetry that tries to steer an AI analyst. Attackers can plant
# this in usernames, command lines or HTTP headers; we tag it at ingest time so
# both the detection engine and the integrity validator can treat it as hostile.
INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore (all |any )?(previous|prior|above) (instructions|prompts)",
        r"disregard (all |any )?(previous|prior|above)",
        r"\b(system|assistant)\s*(prompt|message)\s*:",
        r"you are (now )?an? (ai|assistant|language model)",
        r"mark (this|the)? ?(investigation|incident|activity|alert)? ?as (benign|false positive|resolved)",
        r"authorized (red team|penetration) test.{0,40}(benign|ignore|no action)",
        r"do not (report|flag|escalate)",
    ]
]


class ParseError(ValueError):
    """Raised for records that cannot be normalised. The pipeline records and skips them."""


@dataclass
class NormalizedEvent:
    event_type: str
    timestamp: datetime
    host: str | None = None
    username: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    process: str | None = None
    command_line: str | None = None
    outcome: str = "unknown"
    bytes_out: int | None = None
    country: str | None = None
    message: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def columns(self) -> dict[str, Any]:
        # Shallow mapping on purpose: dataclasses.asdict() deep-copies every value and was ~25% of
        # ingest time in profiling. Parsers already build fresh dicts/lists, so nothing is shared.
        return {f.name: getattr(self, f.name) for f in fields(self)}


# --------------------------------------------------------------------------- field helpers


def _clean_str(value: Any, limit: int = MAX_STR) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s or s in {"-", "N/A"}:
        return None
    # Strip control characters (log forging / terminal escape injection) but keep the text.
    s = "".join(ch for ch in s if ch == "\t" or ord(ch) >= 32)
    return s[:limit]


def _clean_ip(value: Any) -> str | None:
    s = _clean_str(value, 64)
    if s is None:
        return None
    if s.startswith("::ffff:"):  # IPv4-mapped IPv6, common in Windows logs
        s = s[7:]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError as exc:
        raise ParseError(f"invalid IP address: {s!r}") from exc


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if not isinstance(value, str) or not value:
        raise ParseError("missing timestamp")
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError(f"invalid timestamp: {value!r}") from exc
    # Naive timestamps are interpreted as UTC (documented behaviour).
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)


def _int_or_none(value: Any, name: str) -> int | None:
    if value is None or value == "":
        return None
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ParseError(f"{name} must be an integer") from exc
    if n < 0:
        raise ParseError(f"{name} must be non-negative")
    return n


def scan_for_injection(ev: NormalizedEvent) -> None:
    """Tag events whose free-text fields contain AI-steering instructions."""
    haystack = " ".join(
        s for s in (ev.command_line, ev.message, ev.username, ev.process, str(ev.attributes or "")) if s
    )
    if any(p.search(haystack) for p in INJECTION_PATTERNS) and "llm_injection_suspected" not in ev.tags:
        ev.tags.append("llm_injection_suspected")


# --------------------------------------------------------------------------- parser protocol


class Parser(Protocol):
    name: str
    version: str

    def to_raw(self, record: Any, options: dict[str, Any]) -> dict[str, Any]: ...

    def parse(self, raw: dict[str, Any]) -> NormalizedEvent: ...


class NativeParser:
    """TraceLayer's own JSON schema. Unknown keys are preserved in `attributes`."""

    name = "native"
    version = "1"
    _known = {
        "timestamp", "event_type", "host", "user", "username", "src_ip", "dst_ip", "dst_port",
        "process", "command_line", "outcome", "bytes_out", "country", "message", "attributes",
    }  # fmt: skip

    def to_raw(self, record: Any, options: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise ParseError("native records must be JSON objects")
        return record

    def parse(self, raw: dict[str, Any]) -> NormalizedEvent:
        event_type = raw.get("event_type")
        if event_type not in EVENT_TYPES:
            raise ParseError(f"unknown event_type: {event_type!r}")
        outcome = raw.get("outcome", "unknown")
        if outcome not in OUTCOMES:
            raise ParseError(f"invalid outcome: {outcome!r}")
        attributes = dict(raw.get("attributes") or {})
        if not isinstance(attributes, dict):
            raise ParseError("attributes must be an object")
        for k, v in raw.items():
            if k not in self._known:
                attributes[k] = v
        country = _clean_str(raw.get("country"), 2)
        ev = NormalizedEvent(
            event_type=event_type,
            timestamp=_parse_ts(raw.get("timestamp")),
            host=_clean_str(raw.get("host")),
            username=_clean_str(raw.get("username", raw.get("user"))),
            src_ip=_clean_ip(raw.get("src_ip")),
            dst_ip=_clean_ip(raw.get("dst_ip")),
            dst_port=_int_or_none(raw.get("dst_port"), "dst_port"),
            process=_clean_str(raw.get("process")),
            command_line=_clean_str(raw.get("command_line"), MAX_CMD),
            outcome=outcome,
            bytes_out=_int_or_none(raw.get("bytes_out"), "bytes_out"),
            country=country.upper() if country else None,
            message=_clean_str(raw.get("message"), MAX_CMD),
            attributes=attributes,
        )
        scan_for_injection(ev)
        return ev


_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}  # fmt: skip
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
_SSH_FAILED = re.compile(
    r"^Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)  # noqa: E501
_SSH_ACCEPT = re.compile(r"^Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")


class SshdParser:
    """OpenSSH auth.log lines. Syslog omits the year, so it is captured in `raw` at
    ingest time; that keeps re-parsing deterministic during verification."""

    name = "sshd"
    version = "1"

    def to_raw(self, record: Any, options: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(record, str):
            raise ParseError("sshd records must be text lines")
        year = int(options.get("year") or datetime.now(UTC).year)
        return {"line": record.rstrip("\r\n"), "year": year}

    def parse(self, raw: dict[str, Any]) -> NormalizedEvent:
        m = _SYSLOG.match(raw.get("line", ""))
        if not m:
            raise ParseError("not an sshd syslog line")
        month = _MONTHS.get(m["mon"])
        if month is None:
            raise ParseError(f"bad month {m['mon']!r}")
        try:
            hh, mm, ss = (int(x) for x in m["time"].split(":"))
            ts = datetime(int(raw["year"]), month, int(m["day"]), hh, mm, ss, tzinfo=UTC)
        except (ValueError, KeyError) as exc:
            raise ParseError("invalid syslog timestamp") from exc
        msg = m["msg"]
        ev = NormalizedEvent(event_type="other", timestamp=ts, host=_clean_str(m["host"]),
                             process="sshd", message=_clean_str(msg, MAX_CMD))  # fmt: skip
        for pattern, outcome in ((_SSH_FAILED, "failure"), (_SSH_ACCEPT, "success")):
            hit = pattern.match(msg)
            if hit:
                ev.event_type = "auth.login"
                ev.outcome = outcome
                ev.username = _clean_str(hit["user"])
                ev.src_ip = _clean_ip(hit["ip"])
                ev.dst_port = 22
                ev.attributes = {"src_port": int(hit["port"]), "method": "ssh"}
                break
        scan_for_injection(ev)
        return ev


class WinSecParser:
    """Windows Security log records (as exported by e.g. Get-WinEvent | ConvertTo-Json)."""

    name = "winsec"
    version = "1"
    _GROUP_ADD = {4728, 4732, 4756}

    def to_raw(self, record: Any, options: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise ParseError("winsec records must be JSON objects")
        return record

    def parse(self, raw: dict[str, Any]) -> NormalizedEvent:
        try:
            eid = int(raw["EventID"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ParseError("missing EventID") from exc
        ts = _parse_ts(raw.get("TimeCreated"))
        host = _clean_str(raw.get("Computer"))
        ev = NormalizedEvent(event_type="other", timestamp=ts, host=host,
                             attributes={"event_id": eid})  # fmt: skip
        if eid in (4624, 4625):
            ev.event_type = "auth.login"
            ev.outcome = "success" if eid == 4624 else "failure"
            ev.username = _clean_str(raw.get("TargetUserName"))
            ev.src_ip = _clean_ip(raw.get("IpAddress"))
            ev.attributes["logon_type"] = raw.get("LogonType")
        elif eid == 4688:
            ev.event_type = "process.start"
            ev.outcome = "success"
            ev.username = _clean_str(raw.get("SubjectUserName"))
            proc = _clean_str(raw.get("NewProcessName"))
            ev.process = proc.replace("\\", "/").rsplit("/", 1)[-1] if proc else None
            ev.command_line = _clean_str(raw.get("CommandLine"), MAX_CMD)
        elif eid in self._GROUP_ADD:
            ev.event_type = "iam.change"
            ev.outcome = "success"
            ev.username = _clean_str(raw.get("SubjectUserName"))
            ev.attributes.update({"action": "group_add", "group": _clean_str(raw.get("TargetUserName")),
                                  "member": _clean_str(raw.get("MemberName"))})  # fmt: skip
        elif eid == 1102:
            ev.event_type = "log.cleared"
            ev.outcome = "success"
            ev.username = _clean_str(raw.get("SubjectUserName"))
            ev.message = "The audit log was cleared"
        scan_for_injection(ev)
        return ev


PARSERS: dict[str, Parser] = {p.name: p for p in (NativeParser(), SshdParser(), WinSecParser())}


def get_parser(name: str) -> Parser:
    try:
        return PARSERS[name]
    except KeyError as exc:
        raise ParseError(f"unknown parser {name!r}; expected one of {sorted(PARSERS)}") from exc
