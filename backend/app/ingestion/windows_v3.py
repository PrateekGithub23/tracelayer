"""
OTRF / Mordor Windows adapter, schema v3 ("otrf_windows.v3").

Why a new parser name instead of editing "otrf_windows": events are immutable evidence and integrity
verification re-runs the parser recorded on each event. Changing v2's output would make every event it
ingested look tampered. v2 stays frozen; new imports use v3; `tracelayer renormalize` (owner role,
audited) can move existing events to v3 without touching raw records or hashes.

Coverage classification (fixed before any measurement, see docs/REAL_WORLD_DATA_EVALUATION.md):
  full      typed event, and every field this *source event* is expected to provide was normalised
  partial   typed event, but at least one expected field is missing or unparseable (listed in diagnostics)
  raw_only  no typed mapping for this (channel, event id); raw record kept, reason recorded
  (rejected records never reach this parser's output: they fail with ParseError and are counted by the batch)

Class hints use OCSF *concepts and class names* (e.g. "Process Activity"). This is not an OCSF-compliant
output format and is not claimed to be.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.ingestion.parsers import (
    MAX_CMD,
    NormalizedEvent,
    ParseError,
    _clean_str,
    _int_or_none,
    _parse_ts,
    _short_host,
    _split_user,
    redact_credentials,
    scan_for_injection,
)

SCHEMA = "tl-event/3"
SYSMON = "microsoft-windows-sysmon/operational"
SECURITY = "security"
PS_OPS = "microsoft-windows-powershell/operational"
PS_CLASSIC = "windows powershell"
WMI = "microsoft-windows-wmi-activity/operational"


def _base(path: Any) -> str | None:
    p = _clean_str(path)
    return p.replace("\\", "/").rsplit("/", 1)[-1].lower() if p else None


def _ip(value: Any) -> str | None:
    import ipaddress

    s = _clean_str(value, 64)
    if not s:
        return None
    s = s[7:] if s.startswith("::ffff:") else s
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _port(value: Any) -> int | None:
    try:
        return _int_or_none(value, "port")
    except ParseError:
        return None


def _sha256(hashes: Any) -> str | None:
    h = _clean_str(hashes, 1024) or ""
    for part in h.split(","):
        k, _, v = part.partition("=")
        if k.strip().upper() == "SHA256" and v:
            return v.strip().lower()
    return None


class _Ev:
    """Small builder that records which expected fields were actually filled."""

    def __init__(self, ev: NormalizedEvent) -> None:
        self.ev = ev
        self.a = ev.attributes

    def set(self, name: str, value: Any) -> None:
        if value in (None, "", []):
            return
        if name in (
            "username",
            "host",
            "process",
            "command_line",
            "src_ip",
            "dst_ip",
            "dst_port",
            "message",
            "outcome",
        ):
            setattr(self.ev, name, value)
        else:
            self.a[name] = value

    def has(self, name: str) -> bool:
        if name in ("username", "host", "process", "command_line", "src_ip", "dst_ip", "dst_port", "message"):
            return getattr(self.ev, name) not in (None, "")
        return self.a.get(name) not in (None, "", [])


def _user(
    b: _Ev, raw: dict[str, Any], field: str, sid_field: str | None = None, logon_field: str | None = None
) -> None:
    name, domain = _split_user(raw.get(field))
    b.set("username", name)
    b.set("user_domain", domain or _clean_str(raw.get(field.replace("UserName", "DomainName")), 120))
    if sid_field:
        b.set("user_sid", _clean_str(raw.get(sid_field), 200))
    if logon_field:
        b.set("logon_id", _clean_str(raw.get(logon_field), 40))


def _proc(b: _Ev, raw: dict[str, Any], image: str, guid: str | None = None, pid: str | None = None) -> None:
    b.set("process", _base(raw.get(image)))
    b.set("process_path", _clean_str(raw.get(image), 1024))
    if guid:
        b.set("process_guid", _clean_str(raw.get(guid), 64))
    if pid:
        b.set("pid", _clean_str(raw.get(pid), 20))


# --------------------------------------------------------------------------- mapping functions


def m_logon(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success" if eid == 4624 else "failure")
    _user(b, r, "TargetUserName", "TargetUserSid", "TargetLogonId")
    b.set("src_ip", _ip(r.get("IpAddress")))
    b.set("logon_type", _clean_str(r.get("LogonType"), 4))
    b.set("auth_package", _clean_str(r.get("AuthenticationPackageName"), 40))
    b.set("logon_process", _clean_str(r.get("LogonProcessName"), 40))


def m_logoff(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _user(b, r, "TargetUserName", "TargetUserSid", "TargetLogonId")
    b.set("logon_type", _clean_str(r.get("LogonType"), 4))


def m_explicit(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _user(b, r, "SubjectUserName", "SubjectUserSid", "SubjectLogonId")
    b.set("target_user", _split_user(r.get("TargetUserName"))[0])
    b.set("target_server", _clean_str(r.get("TargetServerName"), 255))
    _proc(b, r, "ProcessName")


def m_logon_groups(b: _Ev, r: dict[str, Any], eid: int) -> None:
    _user(b, r, "TargetUserName", "TargetUserSid", "TargetLogonId")
    groups = [g.strip().strip("%{}") for g in str(r.get("GroupMembership") or "").split() if g.strip()]
    b.set("group_count", len(groups) or None)


def m_privs(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    if eid == 4703:
        _user(b, r, "TargetUserName", "TargetUserSid", "TargetLogonId")
        b.set("privileges", (_clean_str(r.get("EnabledPrivilegeList"), 1024) or "").split() or None)
    else:
        _user(b, r, "SubjectUserName", "SubjectUserSid", "SubjectLogonId")
        b.set("privileges", (_clean_str(r.get("PrivilegeList"), 1024) or "").split() or None)
    if eid in (4673, 4674, 4703):
        _proc(b, r, "ProcessName")


def m_proc_create_sec(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _user(b, r, "SubjectUserName", "SubjectUserSid", "SubjectLogonId")
    _proc(b, r, "NewProcessName", pid="NewProcessId")
    b.set("command_line", _clean_str(r.get("CommandLine"), MAX_CMD))
    b.set("parent_process", _base(r.get("ParentProcessName")))
    b.set("parent_path", _clean_str(r.get("ParentProcessName"), 1024))
    b.set("integrity_level", _clean_str(r.get("MandatoryLabel"), 80))


def m_proc_create_sysmon(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _user(b, r, "User")
    _proc(b, r, "Image", "ProcessGuid", "ProcessId")
    b.set("command_line", _clean_str(r.get("CommandLine"), MAX_CMD))
    b.set("parent_process", _base(r.get("ParentImage")))
    b.set("parent_path", _clean_str(r.get("ParentImage"), 1024))
    b.set("parent_guid", _clean_str(r.get("ParentProcessGuid"), 64))
    b.set("parent_pid", _clean_str(r.get("ParentProcessId"), 20))
    b.set("parent_command_line", redact_credentials(_clean_str(r.get("ParentCommandLine"), 2048))[0])
    b.set("integrity_level", _clean_str(r.get("IntegrityLevel"), 40))
    b.set("sha256", _sha256(r.get("Hashes")))
    b.set("logon_id", _clean_str(r.get("LogonId"), 40))


def m_proc_end(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    if eid == 4689:
        _user(b, r, "SubjectUserName", "SubjectUserSid", "SubjectLogonId")
        _proc(b, r, "ProcessName")
    else:
        _proc(b, r, "Image", "ProcessGuid", "ProcessId")


def m_proc_access(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _proc(b, r, "SourceImage", "SourceProcessGUID", "SourceProcessId")
    b.set("target_process", _base(r.get("TargetImage")))
    b.set("target_path", _clean_str(r.get("TargetImage"), 1024))
    b.set("target_guid", _clean_str(r.get("TargetProcessGUID"), 64))
    b.set("granted_access", _clean_str(r.get("GrantedAccess"), 20))


def m_handle_dup(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _user(b, r, "SubjectUserName", "SubjectUserSid", "SubjectLogonId")
    b.set("source_pid", _clean_str(r.get("SourceProcessId"), 20))
    b.set("target_pid", _clean_str(r.get("TargetProcessId"), 20))


def m_object(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _user(b, r, "SubjectUserName", "SubjectUserSid", "SubjectLogonId")
    _proc(b, r, "ProcessName")
    b.set("object_name", _clean_str(r.get("ObjectName"), 1024))
    b.set("object_type", _clean_str(r.get("ObjectType"), 60))
    b.set("handle_id", _clean_str(r.get("HandleId"), 30))
    b.set("access_mask", _clean_str(r.get("AccessMask"), 20))


def m_share(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _user(b, r, "SubjectUserName", "SubjectUserSid", "SubjectLogonId")
    b.set("src_ip", _ip(r.get("IpAddress")))
    b.set("share_name", _clean_str(r.get("ShareName"), 255))
    b.set("object_name", _clean_str(r.get("RelativeTargetName"), 1024))


def m_net_sysmon(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _user(b, r, "User")
    _proc(b, r, "Image", "ProcessGuid", "ProcessId")
    b.set("src_ip", _ip(r.get("SourceIp")))
    b.set("src_port", _port(r.get("SourcePort")))
    b.set("dst_ip", _ip(r.get("DestinationIp")))
    b.set("dst_port", _port(r.get("DestinationPort")))
    b.set("protocol", _clean_str(r.get("Protocol"), 10))
    b.set("direction", "outbound" if str(r.get("Initiated")).lower() == "true" else "inbound")
    b.set("dst_hostname", _clean_str(r.get("DestinationHostname"), 255))


def m_net_wfp(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _proc(b, r, "Application")
    b.set("src_ip", _ip(r.get("SourceAddress")))
    b.set("src_port", _port(r.get("SourcePort")))
    if eid == 5156:
        b.set("dst_ip", _ip(r.get("DestAddress")))
        b.set("dst_port", _port(r.get("DestPort")))
        d = str(r.get("Direction") or "")
        b.set("direction", "inbound" if "14592" in d or "inbound" in d.lower() else "outbound" if d else None)
    b.set("protocol", _clean_str(r.get("Protocol"), 10))
    b.set("action", {5156: "connection_allowed", 5158: "bind", 5154: "listen"}[eid])


def m_policy(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    b.set("change_type", _clean_str(r.get("ChangeType"), 40))
    b.set("policy_name", _clean_str(r.get("FilterName"), 255))
    b.set("layer", _clean_str(r.get("LayerName"), 120))


def m_registry(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _proc(b, r, "Image", "ProcessGuid", "ProcessId")
    b.set("registry_key", _clean_str(r.get("TargetObject"), 1024))
    b.set("action", _clean_str(r.get("EventTypeOrignal") or r.get("EventType"), 40))
    if eid == 13:
        b.set("registry_value", redact_credentials(_clean_str(r.get("Details"), 1024))[0])


def m_module(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _proc(b, r, "Image", "ProcessGuid", "ProcessId")
    b.set("module_path", _clean_str(r.get("ImageLoaded"), 1024))
    b.set("module", _base(r.get("ImageLoaded")))
    b.set("signed", _clean_str(r.get("Signed"), 10))
    b.set("signature_status", _clean_str(r.get("SignatureStatus"), 40))
    b.set("sha256", _sha256(r.get("Hashes")))


def m_file(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _proc(b, r, "Image", "ProcessGuid", "ProcessId")
    b.set("file_path", _clean_str(r.get("TargetFilename"), 1024))
    b.set("message", _clean_str(r.get("TargetFilename"), 1024))  # v2-compatible location of the path


def m_pipe(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _proc(b, r, "Image", "ProcessGuid", "ProcessId")
    b.set("pipe_name", _clean_str(r.get("PipeName"), 255))
    b.set("action", "pipe_created" if eid == 17 else "pipe_connected")


def m_raw_access(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _proc(b, r, "Image", "ProcessGuid", "ProcessId")
    b.set("device", _clean_str(r.get("Device"), 255))


def m_dns(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _proc(b, r, "Image", "ProcessGuid", "ProcessId")
    b.set("query", _clean_str(r.get("QueryName"), 255))
    b.set("message", _clean_str(r.get("QueryName"), 255))


def m_iam(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _user(b, r, "SubjectUserName", "SubjectUserSid", "SubjectLogonId")
    if eid in (4728, 4732, 4756):
        b.set("action", "group_add")
        b.set("group", _clean_str(r.get("TargetUserName")))
        b.set("member", _clean_str(r.get("MemberName")) or _clean_str(r.get("MemberSid")))
    else:
        b.set(
            "action",
            {4720: "account_create", 4722: "account_enable", 4724: "password_reset", 4726: "account_delete"}[eid],
        )
        b.set("target_user", _split_user(r.get("TargetUserName"))[0])


def m_log_cleared(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    _user(b, r, "SubjectUserName", "SubjectUserSid", "SubjectLogonId")
    b.set("message", "The audit log was cleared")


def m_ps_block(b: _Ev, r: dict[str, Any], eid: int) -> None:
    b.set("outcome", "success")
    b.set("script", _clean_str(r.get("ScriptBlockText"), MAX_CMD))
    b.set("message", _clean_str(r.get("ScriptBlockText"), MAX_CMD))
    b.set("script_path", _clean_str(r.get("Path"), 1024))
    b.set("action", "script_block")


def _kv(text: str) -> dict[str, str]:
    """Parse "Key = value" / "Key=value" pairs separated by newlines or ';'. Keys are matched ignoring spaces
    and case, because PowerShell 800 writes "HostApplication=" while 4103 writes "Host Application = "."""
    out: dict[str, str] = {}
    for part in text.replace("\r", "").replace(";", "\n").split("\n"):
        k, sep, v = part.partition("=")
        key = k.strip().replace(" ", "").lower()
        if sep and key and v.strip() and key not in out:
            out[key] = v.strip()
    return out


def m_ps_pipeline(b: _Ev, r: dict[str, Any], eid: int) -> None:
    """4103 module logging and classic 800 pipeline execution: the useful details live in free text."""
    b.set("outcome", "success")
    kv = _kv(str(r.get("ContextInfo") or r.get("Message") or ""))
    host_app = redact_credentials(_clean_str(kv.get("hostapplication"), MAX_CMD))[0]
    b.set("host_application", host_app)
    b.set("command_line", host_app)  # the PowerShell host's command line (e.g. an encoded launcher)
    b.set("command_name", kv.get("commandname"))
    b.set("username", _split_user(kv.get("user") or kv.get("userid"))[0])
    b.set("message", redact_credentials(_clean_str(r.get("Payload") or r.get("Message"), 1024))[0])
    b.set("action", "pipeline_execution")


def m_wmi(b: _Ev, r: dict[str, Any], eid: int) -> None:
    msg = str(r.get("Message") or "")
    kv = _kv(msg)
    b.set("outcome", "failure" if eid == 5858 else "success")
    b.set("message", _clean_str(msg, 1024))
    b.set("process", _base(kv.get("hostprocess")))
    b.set("provider_path", _clean_str(kv.get("providerpath"), 512))
    b.set("operation", _clean_str(kv.get("operation"), 512))
    b.set("result_code", _clean_str(kv.get("resultcode"), 20))
    b.set("username", _split_user(kv.get("user"))[0])
    b.set("action", "wmi_activity")


@dataclass(frozen=True)
class Spec:
    event_type: str
    ocsf: str
    fn: Callable[[_Ev, dict[str, Any], int], None]
    expected: tuple[str, ...]  # fields this source event provides; all present -> "full"


MAPPINGS: dict[tuple[str, int], Spec] = {
    # Security log
    (SECURITY, 4624): Spec("auth.login", "Authentication", m_logon, ("username", "host", "logon_type", "logon_id")),
    (SECURITY, 4625): Spec("auth.login", "Authentication", m_logon, ("username", "host", "logon_type")),
    (SECURITY, 4634): Spec("auth.logoff", "Authentication", m_logoff, ("username", "host", "logon_id")),
    (SECURITY, 4647): Spec("auth.logoff", "Authentication", m_logoff, ("username", "host")),
    (SECURITY, 4648): Spec("auth.explicit_credentials", "Authentication", m_explicit, ("username", "host", "target_user")),
    (SECURITY, 4627): Spec("auth.context", "Authentication", m_logon_groups, ("username", "host", "logon_id")),
    (SECURITY, 4672): Spec("auth.privileges", "Authorize Session", m_privs, ("username", "host", "privileges")),
    (SECURITY, 4673): Spec("auth.privileges", "Authorize Session", m_privs, ("username", "host", "privileges", "process")),
    (SECURITY, 4674): Spec("auth.privileges", "Authorize Session", m_privs, ("username", "host", "privileges", "process")),
    (SECURITY, 4703): Spec("auth.privileges", "Authorize Session", m_privs, ("username", "host", "privileges", "process")),
    (SECURITY, 4688): Spec("process.start", "Process Activity", m_proc_create_sec, ("username", "host", "process", "command_line", "parent_process")),
    (SECURITY, 4689): Spec("process.end", "Process Activity", m_proc_end, ("host", "process")),
    (SECURITY, 4656): Spec("object.access", "File System Activity", m_object, ("username", "host", "process", "object_name", "access_mask")),
    (SECURITY, 4663): Spec("object.access", "File System Activity", m_object, ("username", "host", "process", "object_name", "access_mask")),
    (SECURITY, 4658): Spec("object.access", "File System Activity", m_object, ("username", "host", "process", "handle_id")),
    (SECURITY, 4690): Spec("object.access", "Process Activity", m_handle_dup, ("username", "host", "source_pid", "target_pid")),
    (SECURITY, 5145): Spec("object.access", "SMB Activity", m_share, ("username", "host", "share_name")),
    (SECURITY, 5156): Spec("network.flow", "Network Activity", m_net_wfp, ("host", "process", "src_ip", "dst_ip", "dst_port")),
    (SECURITY, 5158): Spec("network.listen", "Network Activity", m_net_wfp, ("host", "process", "src_port")),
    (SECURITY, 5154): Spec("network.listen", "Network Activity", m_net_wfp, ("host", "process", "src_port")),
    (SECURITY, 5447): Spec("policy.change", "Config State Change", m_policy, ("host", "change_type", "policy_name")),
    (SECURITY, 4720): Spec("iam.change", "Account Change", m_iam, ("username", "host", "target_user")),
    (SECURITY, 4722): Spec("iam.change", "Account Change", m_iam, ("username", "host", "target_user")),
    (SECURITY, 4724): Spec("iam.change", "Account Change", m_iam, ("username", "host", "target_user")),
    (SECURITY, 4726): Spec("iam.change", "Account Change", m_iam, ("username", "host", "target_user")),
    (SECURITY, 4728): Spec("iam.change", "Group Management", m_iam, ("username", "host", "group", "member")),
    (SECURITY, 4732): Spec("iam.change", "Group Management", m_iam, ("username", "host", "group", "member")),
    (SECURITY, 4756): Spec("iam.change", "Group Management", m_iam, ("username", "host", "group", "member")),
    (SECURITY, 1102): Spec("log.cleared", "Event Log Activity", m_log_cleared, ("username", "host")),
    # Sysmon
    (SYSMON, 1): Spec("process.start", "Process Activity", m_proc_create_sysmon, ("username", "host", "process", "command_line", "parent_process", "process_guid", "parent_guid")),
    (SYSMON, 3): Spec("network.flow", "Network Activity", m_net_sysmon, ("host", "process", "src_ip", "dst_ip", "dst_port")),
    (SYSMON, 5): Spec("process.end", "Process Activity", m_proc_end, ("host", "process", "process_guid")),
    (SYSMON, 7): Spec("module.load", "Module Activity", m_module, ("host", "process", "module_path")),
    (SYSMON, 9): Spec("disk.raw_access", "File System Activity", m_raw_access, ("host", "process", "device")),
    (SYSMON, 10): Spec("process.access", "Process Activity", m_proc_access, ("host", "process", "target_process", "granted_access")),
    (SYSMON, 11): Spec("file.access", "File System Activity", m_file, ("host", "process", "file_path")),
    (SYSMON, 12): Spec("registry.change", "Registry Key Activity", m_registry, ("host", "process", "registry_key", "action")),
    (SYSMON, 13): Spec("registry.change", "Registry Value Activity", m_registry, ("host", "process", "registry_key", "registry_value")),
    (SYSMON, 14): Spec("registry.change", "Registry Key Activity", m_registry, ("host", "process", "registry_key")),
    (SYSMON, 17): Spec("ipc.pipe", "Process Activity", m_pipe, ("host", "process", "pipe_name")),
    (SYSMON, 18): Spec("ipc.pipe", "Process Activity", m_pipe, ("host", "process", "pipe_name")),
    (SYSMON, 22): Spec("dns.query", "DNS Activity", m_dns, ("host", "process", "query")),
    # PowerShell and WMI
    (PS_OPS, 4104): Spec("script.exec", "Process Activity", m_ps_block, ("host", "script")),
    (PS_OPS, 4103): Spec("script.exec", "Process Activity", m_ps_pipeline, ("host", "host_application", "command_name", "username")),
    (PS_CLASSIC, 800): Spec("script.exec", "Process Activity", m_ps_pipeline, ("host", "host_application", "username")),
    (WMI, 5857): Spec("wmi.activity", "Process Activity", m_wmi, ("host", "process", "provider_path")),
    (WMI, 5858): Spec("wmi.activity", "Process Activity", m_wmi, ("host", "operation", "result_code")),
    (WMI, 5860): Spec("wmi.activity", "Process Activity", m_wmi, ("host", "operation")),
    (WMI, 5861): Spec("wmi.activity", "Process Activity", m_wmi, ("host", "operation")),
}  # fmt: skip

V3_EVENT_TYPES = frozenset(s.event_type for s in MAPPINGS.values())


class OtrfWindowsV3Parser:
    name = "otrf_windows.v3"
    version = "3"

    def to_raw(self, record: Any, options: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise ParseError("OTRF records must be JSON objects")
        return record

    def parse(self, raw: dict[str, Any]) -> NormalizedEvent:
        try:
            eid = int(raw["EventID"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ParseError("missing EventID") from exc
        if raw.get("@timestamp"):
            ts = _parse_ts(raw["@timestamp"])
        elif raw.get("UtcTime"):
            ts = _parse_ts(str(raw["UtcTime"]).replace(" ", "T") + "Z")
        else:
            raise ParseError("no UTC timestamp (@timestamp/UtcTime); refusing to guess the timezone of EventTime")
        channel_raw = _clean_str(raw.get("Channel"), 120) or "?"
        channel = channel_raw.lower()  # real data mixes "Security" and "security"
        fqdn = _clean_str(raw.get("Hostname"), 255)
        attrs: dict[str, Any] = {
            "event_id": eid, "channel": channel_raw, "provider": _clean_str(raw.get("SourceName"), 120),
            "record_number": raw.get("RecordNumber"), "fqdn": fqdn,
            "source_event_id": f"{fqdn}/{channel_raw}/{raw.get('RecordNumber')}",
            "event_time_local": _clean_str(raw.get("EventTime"), 40),
        }  # fmt: skip
        ev = NormalizedEvent(event_type="other", timestamp=ts, host=_short_host(fqdn), attributes=attrs)
        b = _Ev(ev)
        spec = MAPPINGS.get((channel, eid))
        if spec is None:
            ev.message = _clean_str(raw.get("Message"), 512)
            attrs["norm"] = {"schema": SCHEMA, "status": "raw_only", "missing": [],
                             "reason": f"no v3 mapping for {channel_raw} event {eid}"}  # fmt: skip
        else:
            ev.event_type = spec.event_type
            attrs["ocsf_class"] = spec.ocsf
            spec.fn(b, raw, eid)
            missing = [f for f in spec.expected if not b.has(f)]
            attrs["norm"] = {"schema": SCHEMA, "status": "partial" if missing else "full", "missing": missing,
                             "reason": f"source event lacked: {', '.join(missing)}" if missing else None}  # fmt: skip
        ev.command_line, redacted = redact_credentials(ev.command_line)
        if redacted:
            ev.tags.append("credential_redacted")
        scan_for_injection(ev)
        return ev
