"""
Detection rules.

Each rule is deliberately small, explainable and mapped to MITRE ATT&CK, so an
analyst can see exactly *why* it fired. Thresholds are class attributes, which
keeps them visible and makes them easy to tune or test.

Algorithms are linear (or n log n) over time-ordered events: group by a key,
then slide a window or split into bursts. No rule compares all pairs of events.
"""

import math
import re
from collections import Counter, defaultdict, deque
from datetime import timedelta

from app.detection.base import (
    SEVERITY_ORDER,
    Candidate,
    EventView,
    Rule,
    bucket,
    bursts,
    ent,
    is_external,
    sliding_segments,
)

# Approximate country centroids (lat, lon) for impossible-travel distance estimates.
COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    "CA": (56.1, -106.3), "US": (37.1, -95.7), "MX": (23.6, -102.5), "BR": (-14.2, -51.9),
    "GB": (55.4, -3.4), "IE": (53.4, -8.2), "FR": (46.2, 2.2), "DE": (51.2, 10.4), "NL": (52.1, 5.3),
    "ES": (40.5, -3.7), "IT": (41.9, 12.6), "PL": (51.9, 19.1), "UA": (48.4, 31.2), "RU": (61.5, 105.3),
    "TR": (38.9, 35.2), "IN": (20.6, 78.9), "CN": (35.9, 104.2), "JP": (36.2, 138.3), "KR": (35.9, 127.8),
    "SG": (1.35, 103.8), "AU": (-25.3, 133.8), "NG": (9.1, 8.7), "ZA": (-30.6, 22.9), "IR": (32.4, 53.7),
    "KP": (40.3, 127.5), "VN": (14.1, 108.3), "RO": (45.9, 24.9), "SE": (60.1, 18.6), "AE": (23.4, 53.8),
}  # fmt: skip


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


def _top(values: list[str | None], n: int) -> list[str]:
    return [v for v, _ in Counter(v for v in values if v).most_common(n)]


class BruteForce(Rule):
    id = "TL-AUTH-001"
    name = "Password brute force"
    severity = "medium"
    tactic = "credential-access"
    technique = "T1110"
    description = "At least 10 failed logins from one source address within 10 minutes."
    event_types = frozenset({"auth.login"})
    threshold = 10
    window = timedelta(minutes=10)

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        by_ip: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            if e.event_type == "auth.login" and e.outcome == "failure" and e.src_ip:
                by_ip[e.src_ip].append(e)
        out = []
        for ip, evs in by_ip.items():
            for run in sliding_segments(evs, self.window, self.threshold):
                users = _top([e.username for e in run], 5)
                hosts = _top([e.host for e in run], 3)
                out.append(self.candidate(
                    key=f"{ip}|{int(run[0].timestamp.timestamp())}", events=run,
                    severity="high" if len(run) >= 50 else "medium",
                    confidence=min(0.95, 0.55 + len(run) / 100),
                    summary=f"{len(run)} failed logins from {ip} targeting {', '.join(users) or 'unknown users'}",
                    entities=ent("ip", ip) + [x for u in users for x in ent("user", u)]
                    + [x for h in hosts for x in ent("host", h)],
                ))  # fmt: skip
        return out


class SuccessAfterFailures(Rule):
    id = "TL-AUTH-002"
    name = "Successful login after repeated failures"
    severity = "high"
    tactic = "initial-access"
    technique = "T1078"
    description = "A login succeeds right after an uninterrupted run of 5+ failures from the same source (likely guessed credentials)."
    event_types = frozenset({"auth.login"})
    min_failures = 5
    lookback = timedelta(minutes=30)

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        recent: dict[str, deque[EventView]] = defaultdict(deque)  # src_ip -> recent failures
        out: dict[str, Candidate] = {}
        for e in events:
            if e.event_type != "auth.login" or not e.src_ip:
                continue
            q = recent[e.src_ip]
            while q and e.timestamp - q[0].timestamp > self.lookback:
                q.popleft()
            if e.outcome == "failure":
                q.append(e)
                continue
            if e.outcome != "success":
                continue
            # A success ends the run of failures for this source: a typo followed by a correct password
            # resets the count, so only an uninterrupted run of failures leads to an alert.
            failures, q = list(q), deque()
            recent[e.src_ip] = q
            if len(failures) >= self.min_failures:
                key = f"{e.username}|{e.src_ip}|{bucket(e.timestamp)}"
                if key in out:
                    continue
                evidence = failures[-50:] + [e]
                out[key] = self.candidate(
                    key=key, events=evidence, confidence=min(0.95, 0.6 + len(failures) / 50),
                    summary=f"{e.username} logged in successfully from {e.src_ip} after {len(failures)} failed attempts",
                    entities=ent("user", e.username) + ent("ip", e.src_ip) + ent("host", e.host),
                )  # fmt: skip
        return list(out.values())


class ImpossibleTravel(Rule):
    id = "TL-AUTH-003"
    name = "Impossible travel"
    severity = "high"
    tactic = "initial-access"
    technique = "T1078"
    description = "Successful logins for one user from two countries faster than a commercial flight could travel."
    event_types = frozenset({"auth.login"})
    max_speed_kmh = 900.0

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        last: dict[str, EventView] = {}
        out = []
        for e in events:
            if e.event_type != "auth.login" or e.outcome != "success" or not e.username or not e.country:
                continue
            prev = last.get(e.username)
            last[e.username] = e
            if not prev or not prev.country or prev.country == e.country:
                continue
            a, b = COUNTRY_CENTROIDS.get(prev.country), COUNTRY_CENTROIDS.get(e.country)
            if not a or not b:
                continue
            hours = max((e.timestamp - prev.timestamp).total_seconds() / 3600, 1 / 60)
            speed = haversine_km(a, b) / hours
            if speed > self.max_speed_kmh:
                out.append(self.candidate(
                    key=f"{e.username}|{prev.id}|{e.id}", events=[prev, e], confidence=0.75,
                    summary=(f"{e.username} logged in from {prev.country} then {e.country} "
                             f"{hours * 60:.0f} min apart (~{speed:,.0f} km/h)"),
                    entities=ent("user", e.username) + ent("ip", prev.src_ip) + ent("ip", e.src_ip),
                ))  # fmt: skip
        return out


# (pattern, label, severity, technique)
PROCESS_SIGNATURES: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"powershell(\.exe)?\b.*\s-(e|enc|encodedcommand)\s", re.I), "Encoded PowerShell", "high", "T1059.001"),
    (re.compile(r"\bmimikatz\b|sekurlsa::", re.I), "Credential dumping tool", "critical", "T1003"),
    (re.compile(r"comsvcs(\.dll)?.*minidump", re.I), "LSASS memory dump", "critical", "T1003.001"),
    (re.compile(r"certutil(\.exe)?.*-urlcache", re.I), "Certutil download", "high", "T1105"),
    (re.compile(r"\b(curl|wget)\b[^|]*\|\s*(ba)?sh\b", re.I), "Pipe-to-shell download", "high", "T1105"),
    (re.compile(r"vssadmin(\.exe)?.*delete\s+shadows", re.I), "Shadow copy deletion", "critical", "T1490"),
    (re.compile(r"\bwhoami(\.exe)?\b.*/(priv|groups|all)", re.I), "Privilege discovery", "low", "T1033"),
    # v2 fix (found on OTRF real-world data): `net user ... /add` *creates* an account, which ATT&CK classifies as
    # T1136 Create Account, not T1098 Account Manipulation. Group membership changes remain T1098.
    (re.compile(r"\bnet1?(\.exe)?\s+user\b.*/add\b", re.I), "Account creation (net user /add)", "medium", "T1136.001"),
    (re.compile(r"\bnet1?(\.exe)?\s+(user|group|localgroup)\b.*/(add|domain)", re.I), "Account manipulation",
     "medium", "T1098"),
    (re.compile(r"\bnc(at)?\b.*\s-e\s", re.I), "Reverse shell", "high", "T1059"),
]  # fmt: skip


class SuspiciousProcess(Rule):
    id = "TL-EXEC-001"
    name = "Suspicious command execution"
    severity = "high"
    tactic = "execution"
    technique = "T1059"
    description = "Process command lines matching known attacker tradecraft signatures."
    event_types = frozenset({"process.start"})
    max_gap = timedelta(minutes=60)

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        groups: dict[tuple[str, str], list[tuple[EventView, str, str]]] = defaultdict(list)
        for e in events:
            if e.event_type != "process.start" or not e.command_line:
                continue
            for pattern, label, sev, tech in PROCESS_SIGNATURES:
                if pattern.search(e.command_line):
                    groups[(e.host or "?", label)].append((e, sev, tech))
                    break
        out = []
        for (host, label), hits in groups.items():
            evs = [h[0] for h in hits]
            sev, tech = hits[0][1], hits[0][2]
            for run in bursts(evs, self.max_gap):
                users = _top([e.username for e in run], 3)
                c = self.candidate(
                    key=f"{host}|{label}|{int(run[0].timestamp.timestamp())}", events=run, severity=sev,
                    confidence=0.8, summary=f"{label} on {host} ({len(run)} executions by {', '.join(users) or '?'})",
                    entities=ent("host", host) + [x for u in users for x in ent("user", u)],
                )  # fmt: skip
                c.technique = tech
                c.rule_name = f"{self.name}: {label}"
                out.append(c)
        return out


class PrivilegeEscalation(Rule):
    id = "TL-PRIV-001"
    name = "Account added to privileged group"
    severity = "high"
    tactic = "privilege-escalation"
    technique = "T1098"
    description = "A principal was added to an administrative group."
    event_types = frozenset({"iam.change"})
    privileged = {"administrators", "domain admins", "enterprise admins", "sudo", "wheel", "admins"}

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        out = []
        for e in events:
            a = e.attributes or {}
            group = str(a.get("group") or "")
            if e.event_type != "iam.change" or a.get("action") != "group_add" or group.lower() not in self.privileged:
                continue
            member = a.get("member")
            out.append(self.candidate(
                key=f"{member}|{group}|{bucket(e.timestamp)}", events=[e], confidence=0.85,
                severity="critical" if group.lower() in {"domain admins", "enterprise admins"} else "high",
                summary=f"{member} was added to '{group}' by {e.username or 'unknown'} on {e.host or '?'}",
                entities=ent("user", e.username) + ent("user", member) + ent("host", e.host),
            ))  # fmt: skip
        return out


class LateralMovement(Rule):
    id = "TL-LAT-001"
    name = "Lateral movement: rapid multi-host logons"
    severity = "high"
    tactic = "lateral-movement"
    technique = "T1021"
    description = "One account successfully authenticates to many distinct hosts in a short window."
    event_types = frozenset({"auth.login"})
    min_hosts = 5  # normal users touch their workstation + a few shared servers; 5+ in 30 min is unusual
    window = timedelta(minutes=30)

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        by_user: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            if e.event_type == "auth.login" and e.outcome == "success" and e.username and e.host:
                by_user[e.username].append(e)
        out = []
        for user, evs in by_user.items():
            # Two-pointer sliding window; qualifying windows are merged into segments.
            segments: list[list[int]] = []
            hosts: Counter[str] = Counter()
            left = 0
            for right, e in enumerate(evs):
                hosts[e.host or ""] += 1
                while e.timestamp - evs[left].timestamp > self.window:
                    hosts[evs[left].host or ""] -= 1
                    if hosts[evs[left].host or ""] == 0:
                        del hosts[evs[left].host or ""]
                    left += 1
                if len(hosts) >= self.min_hosts:
                    if segments and left <= segments[-1][1]:
                        segments[-1][1] = right
                    else:
                        segments.append([left, right])
            for start, end in segments:
                seg = evs[start : end + 1]
                distinct = sorted({x.host for x in seg if x.host})
                out.append(self.candidate(
                    key=f"{user}|{int(seg[0].timestamp.timestamp())}", events=seg,
                    confidence=min(0.95, 0.5 + 0.08 * len(distinct)),
                    summary=f"{user} authenticated to {len(distinct)} distinct hosts in "
                            f"{(seg[-1].timestamp - seg[0].timestamp).total_seconds() / 60:.0f} min",
                    entities=ent("user", user) + [x for h in distinct for x in ent("host", h)],
                ))  # fmt: skip
        return out


class Exfiltration(Rule):
    id = "TL-EXFIL-001"
    name = "Large outbound transfer to external host"
    severity = "high"
    tactic = "exfiltration"
    technique = "T1048"
    description = "A host sends 50 MB+ to one external address within 60 minutes."
    event_types = frozenset({"network.flow"})
    threshold_bytes = 50 * 1024 * 1024
    critical_bytes = 500 * 1024 * 1024
    window = timedelta(minutes=60)

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        groups: dict[tuple[str, str], list[EventView]] = defaultdict(list)
        for e in events:
            if e.event_type == "network.flow" and e.bytes_out and is_external(e.dst_ip):
                groups[(e.host or "?", e.dst_ip or "?")].append(e)
        out = []
        for (host, dst), evs in groups.items():
            for run in sliding_segments(evs, self.window, self.threshold_bytes, lambda e: float(e.bytes_out or 0)):
                total = sum(e.bytes_out or 0 for e in run)
                out.append(self.candidate(
                    key=f"{host}|{dst}|{int(run[0].timestamp.timestamp())}", events=run,
                    severity="critical" if total >= self.critical_bytes else "high",
                    confidence=min(0.95, 0.6 + total / (2 * self.critical_bytes)),
                    summary=f"{host} sent {total / 1024 / 1024:.1f} MB to {dst} in {len(run)} flows",
                    entities=ent("host", host) + ent("ip", dst),
                ))  # fmt: skip
        return out


class LogTampering(Rule):
    id = "TL-DEF-001"
    name = "Security log cleared"
    severity = "high"
    tactic = "defense-evasion"
    technique = "T1070.001"
    description = "Audit logs were cleared or deleted, destroying evidence."
    event_types = frozenset({"log.cleared", "process.start"})
    _cmd = re.compile(r"wevtutil(\.exe)?\s+(cl|clear-log)\b|Clear-EventLog|rm\s+-rf?\s+/var/log|history\s+-c", re.I)

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        groups: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            if e.event_type == "log.cleared" or (e.event_type == "process.start" and e.command_line
                                                  and self._cmd.search(e.command_line)):  # fmt: skip
                groups[f"{e.host}|{bucket(e.timestamp)}"].append(e)
        return [
            self.candidate(
                key=key,
                events=evs,
                confidence=0.9,
                summary=f"Security logs cleared on {evs[0].host or '?'} by {evs[0].username or 'unknown'}",
                entities=ent("host", evs[0].host) + ent("user", evs[0].username),
            )  # fmt: skip
            for key, evs in groups.items()
        ]


class RemoteWmiExecution(Rule):
    """ATT&CK T1047 (Windows Management Instrumentation). Detection guidance: process creation through WMI,
    i.e. `wmic /node:<remote> process call create`, or the WMI provider host (WmiPrvSE.exe) spawning a
    command interpreter or living-off-the-land binary. Written from the ATT&CK description (v2)."""

    id = "TL-EXEC-002"
    name = "Process execution through WMI"
    severity = "high"
    tactic = "execution"
    technique = "T1047"
    description = (
        "Remote or local process creation via WMI (wmic process call create, or WmiPrvSE.exe spawning a shell/LOLBin)."
    )
    event_types = frozenset({"process.start"})
    _wmic_create = re.compile(r"\bwmic(\.exe)?\b.*\bprocess\s+call\s+create\b", re.I)
    _wmic_remote = re.compile(r"/node:\s*\"?([^\s\"]+)", re.I)
    _children = {"cmd.exe", "powershell.exe", "pwsh.exe", "net.exe", "net1.exe", "rundll32.exe", "mshta.exe",
                 "cscript.exe", "wscript.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}  # fmt: skip

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        groups: dict[tuple[str, str], list[EventView]] = defaultdict(list)
        for e in events:
            if e.event_type != "process.start":
                continue
            parent = str((e.attributes or {}).get("parent_process") or "").lower()
            if e.command_line and self._wmic_create.search(e.command_line):
                m = self._wmic_remote.search(e.command_line)
                groups[(e.host or "?", f"wmic → {m.group(1).lower()}" if m else "wmic (local)")].append(e)
            elif parent == "wmiprvse.exe" and (e.process or "").lower() in self._children:
                groups[(e.host or "?", f"WmiPrvSE spawned {e.process}")].append(e)
        out = []
        for (host, how), evs in groups.items():
            for run in bursts(sorted(evs, key=lambda x: x.timestamp), timedelta(minutes=30)):
                users = _top([e.username for e in run], 3)
                target = how.split("→ ")[1] if "→ " in how else None
                out.append(self.candidate(
                    key=f"{host}|{how}|{bucket(run[0].timestamp)}", events=run, confidence=0.8,
                    summary=f"Process execution through WMI on {host}: {how} ({len(run)} event(s), user {', '.join(users) or '?'})",
                    entities=ent("host", host) + ent("host", target) + [x for u in users for x in ent("user", u)],
                ))  # fmt: skip
        return out


class LocalAccountCreated(Rule):
    """ATT&CK T1136.001 (Create Account: Local Account). Data source: Windows Security 4720 / user-account
    creation events, normalised as iam.change action=account_create (v2)."""

    id = "TL-PERS-001"
    name = "New account created"
    severity = "medium"
    tactic = "persistence"
    technique = "T1136.001"
    description = "A user account was created. Legitimate in provisioning workflows; suspicious when created by a non-IT user or alongside other detections."
    event_types = frozenset({"iam.change"})

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        out = []
        for e in events:
            a = e.attributes or {}
            if e.event_type != "iam.change" or a.get("action") != "account_create":
                continue
            target = a.get("target_user")
            out.append(self.candidate(
                key=f"{e.host}|{target}|{bucket(e.timestamp)}", events=[e], confidence=0.7,
                summary=f"Account '{target or '?'}' created on {e.host or '?'} by {e.username or 'unknown'}",
                entities=ent("host", e.host) + ent("user", e.username) + ent("user", target),
            ))  # fmt: skip
        return out


class TelemetryInjection(Rule):
    id = "TL-AI-001"
    name = "Adversarial instructions embedded in telemetry"
    severity = "medium"
    tactic = "defense-evasion"
    technique = "AML.T0051"  # MITRE ATLAS: LLM prompt injection
    description = "Log content attempts to instruct an AI analyst (prompt injection via telemetry)."
    event_types = frozenset({"auth.login", "process.start", "network.flow", "iam.change", "dns.query",
                             "file.access", "log.cleared", "other"})  # fmt: skip

    def evaluate(self, events: list[EventView]) -> list[Candidate]:
        groups: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            if "llm_injection_suspected" in (e.tags or []):
                groups[f"{e.host}|{bucket(e.timestamp)}"].append(e)
        return [
            self.candidate(
                key=key,
                events=evs,
                confidence=0.7,
                summary=f"{len(evs)} event(s) on {evs[0].host or '?'} contain text that tries to steer AI analysis",
                entities=ent("host", evs[0].host) + ent("user", evs[0].username),
            )  # fmt: skip
            for key, evs in groups.items()
        ]


ALL_RULES: list[Rule] = [
    BruteForce(), SuccessAfterFailures(), ImpossibleTravel(), SuspiciousProcess(), PrivilegeEscalation(),
    LateralMovement(), Exfiltration(), LogTampering(), TelemetryInjection(), RemoteWmiExecution(), LocalAccountCreated(),
]  # fmt: skip

assert all(r.severity in SEVERITY_ORDER for r in ALL_RULES)
