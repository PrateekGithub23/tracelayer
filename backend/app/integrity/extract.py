"""
Assertion extraction: turn a natural-language claim into checkable facts.

We deliberately do NOT ask the model to also emit structured facts: the text is
what an analyst reads, so the text is what must be verified. Extraction is
rule-based and deterministic (no ML), which keeps verdicts reproducible and
explainable. The trade-off is recall: phrasing the lexicon does not cover is
not checked, so unrecognised facts can never *raise* a claim's verdict. A claim
with no recognised facts and no citations is still unsupported.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from app.integrity.scope import Scope

# --------------------------------------------------------------------------- lexicons


@dataclass(frozen=True)
class Mention:
    """A reference to a kind of activity, e.g. 'failed logins' -> auth.login/failure."""

    label: str
    types: frozenset[str]
    outcome: str | None = None
    keyword: str | None = None  # must appear in command line / process / group / message
    external_only: bool = False
    start: int = 0
    negated: bool = False


_ACTIVITY: list[tuple[str, str, frozenset[str], str | None, str | None, bool]] = [
    # (regex, label, event types, outcome, keyword, external destination only)
    (r"failed (?:login|logon|authentication|password|sign-in)s?|(?:login|logon|authentication) (?:failures?|attempts)"
     r"|brute[- ]?forc\w*|password (?:guessing|spraying)|failed attempts",
     "failed authentication", frozenset({"auth.login"}), "failure", None, False),
    (r"successful(?:ly)? (?:login|logon|authenticat\w*|sign-in)|logged (?:in|on)|log (?:in|on) successfully"
     r"|authenticated (?:successfully|to|as)|signed in|valid credentials|successful(?:ly)? logged|logging (?:in|on) to",
     "successful authentication", frozenset({"auth.login"}), "success", None, False),
    (r"(?:encoded )?powershell", "PowerShell execution", frozenset({"process.start"}), None, "powershell", False),
    (r"certutil", "certutil execution", frozenset({"process.start"}), None, "certutil", False),
    (r"whoami", "whoami execution", frozenset({"process.start"}), None, "whoami", False),
    (r"mimikatz", "mimikatz execution", frozenset({"process.start"}), None, "mimikatz", False),
    (r"wevtutil|(?:security|audit|event) logs? (?:was |were )?(?:cleared|wiped|deleted)|cleared the \w+ log"
     r"|log clearing|cleared (?:the )?(?:security |audit )?logs?",
     "log clearing", frozenset({"log.cleared", "process.start"}), None, None, False),
    (r"executed|ran (?:the )?commands?|command[- ]lines?|process(?:es)? (?:start|creation|execution)",
     "process execution", frozenset({"process.start"}), None, None, False),
    (r"domain admins", "Domain Admins membership change", frozenset({"iam.change"}), None, "domain admins", False),
    (r"added to (?:the )?['\"]?[\w ]{0,30}(?:group|admins)|privilege escalation|privileged group|elevated privileges",
     "privileged group change", frozenset({"iam.change"}), None, None, False),
    (r"exfiltrat\w*|outbound (?:data )?transfers?|data transfer|uploaded|sent [\d.,]+ ?(?:mb|gb|mib|gib)",
     "outbound transfer", frozenset({"network.flow"}), None, None, True),
    (r"(?:network|outbound) (?:flows?|connections?|traffic)", "network activity", frozenset({"network.flow"}),
     None, None, False),
    (r"instruct\w* (?:the )?(?:ai|llm|language model)s?(?: analysts?)?|prompt injection|adversarial (?:instructions|content|text)",
     "AI-directed instructions", frozenset({"auth.login", "process.start", "network.flow", "iam.change", "dns.query",
                                            "file.access", "log.cleared", "other"}), None, None, False),
    (r"dns (?:quer(?:y|ies)|lookups?|requests?)", "DNS queries", frozenset({"dns.query"}), None, None, False),
    (r"file (?:access|reads?)|accessed files?", "file access", frozenset({"file.access"}), None, None, False),
]  # fmt: skip
_ACTIVITY_RE = [(re.compile(rx, re.I), lbl, t, o, k, x) for rx, lbl, t, o, k, x in _ACTIVITY]

# "process telemetry", "network logs" ... used in coverage-gap statements.
_TELEMETRY_WORDS = {
    "process": "process.start", "endpoint": "process.start", "network": "network.flow",
    "authentication": "auth.login", "auth": "auth.login", "dns": "dns.query", "file": "file.access",
}  # fmt: skip
_GAP_RE = re.compile(
    r"\bno (process|endpoint|network|authentication|auth|dns|file) (?:telemetry|logs?|data|events|visibility)"
    r"|\b(process|endpoint|network|authentication|auth|dns|file) (?:telemetry|logs?|data|events) (?:was|were|is|are) "
    r"(?:not|never) (?:collected|ingested|available|present)"
    r"|\bmissing (process|endpoint|network|authentication|auth|dns|file) (?:telemetry|logs?|data)",
    re.I,
)  # fmt: skip

_NEGATION_RE = re.compile(
    r"\b(?:no|not|never|without|absence of|did not|didn't|no evidence of|no sign of|no indication of)\s+"
    r"(?:\w+\s+){0,2}$",
    re.I,
)
_HEDGE_RE = re.compile(
    r"\b(may|might|could|possibly|potentially|likely|probably|suggests?|appears? to|seems? to|perhaps"
    r"|hypothes\w+|suspected|unconfirmed|we suspect|it is plausible)\b",
    re.I,
)
_CORRELATION_RE = re.compile(
    r"\b(followed by|then|after|before|subsequently|later|led to|leading to|linked|correlat\w+|same (?:ip|user|"
    r"host|account|address)|consistent with|indicat\w+|pivot\w*|progress\w*|chain|sequence|following)\b",
    re.I,
)
_DISMISSIVE_RE = re.compile(
    r"\b(?:is|was|are|were|appears?|seems?)\s+(?:to be\s+)?(?:likely\s+)?(?:benign|legitimate|authori[sz]ed|"
    r"expected|harmless)\b|false positive|no (?:further )?action (?:is )?(?:needed|required)|safe to (?:close|ignore)"
    r"|not malicious|no threat",
    re.I,
)
_REPORTED_SPEECH_RE = re.compile(r"\b(instruct\w*|inject\w*|attempts? to|tries to|trying to|adversarial|"
                                 r"manipulat\w*|steer)\b", re.I)  # fmt: skip

_FORWARD = re.compile(r"\b(followed by|then|before|prior to|leading to|led to|subsequently|and later)\b", re.I)
_BACKWARD = re.compile(r"\b(after|following|preceded by)\b", re.I)

_COUNT_FAILED = re.compile(
    r"\b(?P<q>at least |more than |over |approximately |about |~)?(?P<n>\d[\d,]*)\s+(?:failed|unsuccessful)\s+"
    r"(?:\w+\s+)?(?:attempts?|logins?|logons?|failures?|authentications?|passwords?|sign-ins?)",
    re.I,
)
_COUNT_HOSTS = re.compile(
    r"\b(?P<q>at least |more than |over |approximately |about |~)?(?P<n>\d+)\s+(?:distinct |different |separate "
    r"|unique )?(?:hosts|systems|machines|servers)",
    re.I,
)
_COUNT_FLOWS = re.compile(
    r"\b(?P<q>at least |more than |over |approximately |about |~)?(?P<n>\d+)\s+(?:network |outbound )?(?:flows|"
    r"connections|transfers)",
    re.I,
)
_VOLUME = re.compile(
    r"\b(?P<q>at least |more than |over |approximately |about |~)?(?P<n>\d+(?:\.\d+)?)\s*(?P<u>mb|gb|mib|gib)\b", re.I
)

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)")
_REF_TOKENS = re.compile(r"\[?\b(?:E\d+|D\d+|evt_[0-9a-f]{20}|det_[0-9a-f]{20})\b\]?")
_TOKEN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-$@\\]*")
_LIST_TAIL = r"['\"`]?(?P<names>[\w.\-$@\\]+(?:(?:,\s*|\s+and\s+|,\s+and\s+)['\"`]?[\w.\-$@\\]+)*)"
_USER_KW = re.compile(r"\b(?:users?|accounts?|usernames?|principals?)\s+" + _LIST_TAIL, re.I)
_HOST_KW = re.compile(r"\b(?:hosts?|servers?|workstations?|machines?|endpoints?)\s+" + _LIST_TAIL, re.I)

# Words that follow "user"/"host" in ordinary prose and are never entity names.
_STOP = {
    "a", "an", "the", "was", "were", "is", "are", "and", "or", "of", "to", "on", "in", "from", "that", "which",
    "who", "with", "by", "for", "logged", "logins", "login", "logon", "accounts", "account", "names", "name",
    "activity", "had", "has", "have", "then", "credentials", "session", "sessions", "it", "its", "this", "these",
    "those", "telemetry", "there", "be", "been", "being", "as", "at", "also", "after", "before", "authenticated",
    "attempted", "targeted", "involved", "list", "level", "group", "groups", "host", "hosts", "user", "users",
    "within", "over", "across", "during", "inside", "under", "between", "via", "through", "into", "onto", "using",
    "while", "where", "when", "both", "all", "each", "multiple", "several", "other", "same", "new", "remote",
    "entities", "entity", "include", "including", "such", "like", "named", "listed",
}  # fmt: skip
# Real usernames that are also ordinary words: only counted when introduced by "user X".
_COMMON_NAMES = {"admin", "root", "test", "guest", "service", "backup", "support", "info", "mail", "web", "oracle",
                 "postgres", "ubuntu"}  # fmt: skip


@dataclass
class Assertions:
    ips: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    unknown_entities: list[str] = field(default_factory=list)  # named but unseen anywhere
    mentions: list[Mention] = field(default_factory=list)
    counts: list[dict[str, Any]] = field(default_factory=list)  # {kind, n, qualifier}
    gap_types: list[str] = field(default_factory=list)
    hedged: bool = False
    correlational: bool = False
    dismissive: bool = False
    text: str = ""


def _split_names(blob: str) -> list[str]:
    parts = re.split(r",\s*and\s+|,\s*|\s+and\s+", blob)
    return [p.strip("'\"`.,;:()") for p in parts if p.strip("'\"`.,;:()")]


def _clean_token(tok: str) -> str:
    tok = tok.rstrip(".,;:!?)'\"")
    return tok[:-2] if tok.endswith("'s") else tok


def extract(text: str, scope: Scope) -> Assertions:
    a = Assertions(text=text)
    body = _REF_TOKENS.sub(" ", text)
    lower = body.lower()

    # ---- IP addresses
    for m in _IPV4.finditer(body):
        try:
            a.ips.add(str(ipaddress.ip_address(m.group(0))))
        except ValueError:
            continue

    # ---- users and hosts: keyword-introduced names (may be unknown) + known vocabulary tokens
    for rx, kind, bag in ((_USER_KW, "user", a.users), (_HOST_KW, "host", a.hosts)):
        other_vocab = scope.vocab_hosts if kind == "user" else scope.vocab_users
        for m in rx.finditer(body):
            for position, name in enumerate(_split_names(m.group("names"))):
                n = _clean_token(name)
                if not n or n.lower() in _STOP or _IPV4.fullmatch(n) or n.isdigit():
                    continue
                if scope.entity_exists(kind, n):
                    bag.add(n.lower())
                elif n.lower() in other_vocab:
                    continue  # e.g. "user web-01": names the other entity type; picked up by the token pass
                # An unknown name is flagged as fabricated only when we are confident it was meant as a
                # name: the first item after the keyword, or anything identifier-shaped (digits, '-', '_').
                # This stops prose like "users alice and later" from producing a false "user:later".
                elif (position == 0 and len(n) >= 3) or re.search(r"[\d\-_]", n):
                    a.unknown_entities.append(f"{kind}:{n}")
    for tok in _TOKEN.findall(body):
        t = _clean_token(tok).lower()
        if t in scope.vocab_hosts:
            a.hosts.add(t)
        elif t in scope.vocab_users and t not in _COMMON_NAMES and t not in _STOP:
            a.users.add(t)
    for ip in a.ips:
        if not scope.entity_exists("ip", ip):
            a.unknown_entities.append(f"ip:{ip}")

    # ---- activity mentions (with negation detected from the words just before each mention)
    for rx, label, types, outcome, keyword, external in _ACTIVITY_RE:
        for m in rx.finditer(body):
            negated = bool(_NEGATION_RE.search(body[max(0, m.start() - 40) : m.start()]))
            if any(abs(x.start - m.start()) < 3 and x.types == types for x in a.mentions):
                continue
            a.mentions.append(Mention(label, types, outcome, keyword, external, m.start(), negated))
    a.mentions.sort(key=lambda x: x.start)
    # A specific mention (e.g. "PowerShell") subsumes a generic one ("executed") on the same type.
    specific = {t for x in a.mentions if x.keyword for t in x.types}
    a.mentions = [x for x in a.mentions if x.keyword or x.outcome or x.external_only or not (x.types & specific)]

    for m in _GAP_RE.finditer(body):
        word = next(g for g in m.groups() if g)
        a.gap_types.append(_TELEMETRY_WORDS[word.lower()])

    # ---- quantities
    for rx, kind in ((_COUNT_FAILED, "failed_auth"), (_COUNT_HOSTS, "distinct_hosts"), (_COUNT_FLOWS, "flows")):
        for m in rx.finditer(body):
            a.counts.append(
                {"kind": kind, "n": int(m["n"].replace(",", "")), "qualifier": (m["q"] or "").strip().lower()}
            )
    for m in _VOLUME.finditer(body):
        mult = 1024**3 if m["u"].lower() in ("gb", "gib") else 1024**2
        a.counts.append({"kind": "bytes", "n": float(m["n"]) * mult, "qualifier": (m["q"] or "").strip().lower()})

    # ---- framing
    a.hedged = bool(_HEDGE_RE.search(lower))
    a.correlational = bool(_CORRELATION_RE.search(lower))
    a.dismissive = bool(_DISMISSIVE_RE.search(lower)) and not _REPORTED_SPEECH_RE.search(lower)
    return a


def temporal_pairs(a: Assertions) -> list[tuple[Mention, Mention]]:
    """Ordered (earlier, later) mention pairs implied by connectors between adjacent mentions."""
    pairs = []
    ms = [m for m in a.mentions if not m.negated]
    body = _REF_TOKENS.sub(" ", a.text)
    for first, second in zip(ms, ms[1:], strict=False):
        between = body[first.start : second.start]
        if first.types == second.types and first.outcome == second.outcome:
            continue
        if _BACKWARD.search(between):
            pairs.append((second, first))
        elif _FORWARD.search(between):
            pairs.append((first, second))
    return pairs
