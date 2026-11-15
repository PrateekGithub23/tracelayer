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
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
     r"|authenticated (?:successfully|to|as)|signed in|valid credentials|successful(?:ly)? logged|logging (?:in|on) to"
     r"|gained (?:\w+ )?access to|got into|broke into",
     "successful authentication", frozenset({"auth.login"}), "success", None, False),
    (r"(?:encoded )?powershell", "PowerShell execution", frozenset({"process.start"}), None, "powershell", False),
    (r"certutil", "certutil execution", frozenset({"process.start"}), None, "certutil", False),
    (r"whoami", "whoami execution", frozenset({"process.start"}), None, "whoami", False),
    (r"mimikatz", "mimikatz execution", frozenset({"process.start"}), None, "mimikatz", False),
    (r"wevtutil|(?:security|audit|event) logs?(?: \S+){0,3}? (?:was |were |has been |had been )?(?:cleared|wiped|deleted|erased)"
     r"|cleared the \w+ log|log clearing|cleared (?:the )?(?:security |audit )?logs?",
     "log clearing", frozenset({"log.cleared", "process.start"}), None, None, False),
    (r"executed|ran (?:the )?commands?|command[- ]lines?|process(?:es)? (?:start|creation|execution)",
     "process execution", frozenset({"process.start"}), None, None, False),
    (r"domain admins", "Domain Admins membership change", frozenset({"iam.change"}), None, "domain admins", False),
    (r"added to (?:the )?['\"]?[\w ]{0,30}(?:group|admins)|privilege escalation|privileged group|elevated privileges"
     r"|(?:administrative|admin|privileged) (?:group )?(?:membership|rights|privileges)",
     "privileged group change", frozenset({"iam.change"}), None, None, False),
    (r"exfiltrat\w*|outbound (?:data )?transfers?|data transfer|uploaded"
     r"|(?:sent|send|transferred|transfer|moved|copied|uploaded)(?: \w+){0,2}? (?:[\d.,]+ ?(?:mb|gb|mib|gib)|data|bytes|files)\b"
     r"|[\d.,]+ ?(?:mb|gb|mib|gib) (?:was |were )?(?:sent|transferred|left|uploaded|exfiltrated)",
     "outbound transfer", frozenset({"network.flow"}), None, None, True),
    (r"(?:network|outbound) (?:flows?|connections?|traffic)", "network activity", frozenset({"network.flow"}),
     None, None, False),
    (r"instruct\w* (?:the )?(?:ai|llm|language model)s?(?: analysts?)?|prompt injection|adversarial (?:instructions|content|text)",
     "AI-directed instructions", frozenset({"auth.login", "process.start", "network.flow", "iam.change", "dns.query",
                                            "file.access", "log.cleared", "other"}), None, None, False),
    (r"dump(?:ed|ing)? credentials|credentials? (?:dump\w*|theft|harvest\w*)|harvest(?:ed|ing)? credentials"
     r"|lsass(?: memory)?|sekurlsa|credentials? from memory",
     "credential dumping", frozenset({"process.start"}), None, None, False),
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
    r"|\bmissing (process|endpoint|network|authentication|auth|dns|file) (?:telemetry|logs?|data)"
    r"|\b(process|endpoint|network|authentication|auth|dns|file) (?:telemetry|logs?|data|events|visibility) "
    r"(?:is|are|was|were) (?:missing|absent|unavailable|not available)",
    re.I,
)  # fmt: skip

_NEGATION_RE = re.compile(
    r"\b(?:no|not|never|without|absence of|did not|didn't|no evidence of|no sign of|no indication of)\s+"
    r"(?:\w+\s+){0,2}$",
    re.I,
)
# v2: a negation cue anywhere earlier in the same clause ("At no point was the log on dc-01 cleared").
_CLAUSE_NEGATION_RE = re.compile(
    r"\b(?:never|did not|didn't|does not|doesn't|was not|wasn't|were not|weren't|has not|hasn't|have not|"
    r"at no (?:point|time|stage)|no evidence of|no sign of|no indication of)\b",
    re.I,
)
# Punctuation only ends a clause when followed by whitespace: "198.51.100.77" and "11:09" are not breaks.
_CLAUSE_BREAK = re.compile(r"[.;:!?](?=\s|$)|,\s|\bbut\b|\bhowever\b|\bwhereas\b|\balthough\b", re.I)
_QUANT_PHRASE = re.compile(r"\bno (?:more|fewer|less) than\b", re.I)
_UNIVERSAL_FAIL_RE = re.compile(
    r"\b(?:every|all|each)\b(?: \w+){0,3}? (?:login|logon|sign-in|authentication)s?(?: attempts?)?(?: \S+){0,4}? "
    r"(?:failed|was unsuccessful|were unsuccessful|was rejected|were rejected)\b",
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
    r"|not malicious|no threat"
    # v2 paraphrases of "nothing to see here"
    r"|\broutine (?:\w+ )?(?:activity|maintenance|patching|traffic|behaviou?r|admin\w*)|\bnormal (?:\w+ ){0,2}"
    r"(?:behaviou?r|traffic|activity|operations?)|(?:safely|can) (?:be )?(?:ignored?|closed)|nothing to worry about"
    r"|nothing (?:here )?(?:is |was )?(?:malicious|suspicious)|not (?:a |an )?(?:threat|concern|incident)",
    re.I,
)
# v2: conclusions telemetry cannot establish. Attribution, intent and physical location are inferences;
# stated as fact they are unsupported, hedged they are hypotheses.
_CONCLUSION_RE = re.compile(
    r"\b(?:nation[- ]state|state[- ]sponsored|apt ?\d+|apt group|insider (?:threat|attack|job)|organi[sz]ed crim\w*|"
    r"(?:criminal|ransomware|threat) (?:group|gang|actor)|financially motivated|espionage|attributed to|"
    r"(?:attacker|actor|adversary|operator)s? (?:is|are|was|were) (?:based|located|operating) in|based in [A-Z]\w+)",
    re.I,
)
_PROOF_RE = re.compile(r"\b(?:proves?|proven|confirms? that|demonstrates? that|establishes that|conclusively)\b", re.I)
# v2: appeals to authority or prior approval are social engineering aimed at the reviewer.
_AUTHORITY_RE = re.compile(
    r"\b(?:pre-?approved|approved by|signed off by|sanctioned|authori[sz]ed by|note to (?:the )?reviewers?|"
    r"(?:soc|security|it) (?:lead|manager|director|team) (?:has |have )?(?:approved|confirmed|cleared|signed off)|"
    r"incident commander|already (?:been )?(?:reviewed|approved|cleared))\b",
    re.I,
)
_REPORTED_SPEECH_RE = re.compile(r"\b(instruct\w*|inject\w*|attempts? to|tries to|trying to|adversarial|"
                                 r"manipulat\w*|steer)\b", re.I)  # fmt: skip

_FORWARD = re.compile(r"\b(followed by|then|before|prior to|leading to|led to|subsequently|and later)\b", re.I)
_BACKWARD = re.compile(r"\b(after|following|preceded by)\b", re.I)

_QUAL = (
    r"(?P<q>at least |more than |over |upwards of |in excess of |approximately |about |roughly |around |~|"
    r"fewer than |less than |under |at most |no more than |up to )?"
)
_COUNT_SUCCESS = re.compile(
    r"\b" + _QUAL + r"(?P<n>\d[\d,]*)\s+successful\s+(?:\w+\s+)?(?:logins?|logons?|sign-ins?|authentications?)", re.I
)
_COUNT_TIMES = re.compile(r"\b" + _QUAL + r"(?:exactly )?(?P<n>\d+)\s+times\b|\b(?P<w>once|twice)\b", re.I)
_COUNT_FAILED = re.compile(
    r"\b(?P<q>at least |more than |over |upwards of |in excess of |approximately |about |roughly |around |~|"
    r"fewer than |less than |under |at most |no more than |up to )?(?P<n>\d[\d,]*)\s+(?:failed|unsuccessful)\s+"
    r"(?:\w+\s+)?(?:attempts?|logins?|logons?|failures?|authentications?|passwords?|sign-ins?)",
    re.I,
)
_COUNT_HOSTS = re.compile(
    r"\b(?P<q>at least |more than |over |approximately |about |roughly |~|fewer than |less than |under |at most |no more than )?(?P<n>\d+)\s+(?:distinct |different |separate "
    r"|unique )?(?:hosts|systems|machines|servers)",
    re.I,
)
_COUNT_FLOWS = re.compile(
    r"\b(?P<q>at least |more than |over |approximately |about |roughly |~|fewer than |less than |under |at most |no more than )?(?P<n>\d+)\s+(?:network |outbound )?(?:flows|"
    r"connections|transfers)",
    re.I,
)
_VOLUME = re.compile(
    r"\b(?P<q>at least |more than |over |approximately |about |roughly |around |~|fewer than |less than |under |at most |no more than )?(?P<n>\d+(?:\.\d+)?)\s*(?P<u>mb|gb|mib|gib)\b",
    re.I,
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
    # v2
    times: list[dict[str, Any]] = field(default_factory=list)  # {text, utc (datetime|None), minutes, tz, assumed_utc}
    conclusions: list[str] = field(default_factory=list)  # attribution / intent / location inferences
    proof_language: bool = False
    authority: bool = False
    deceptive: list[str] = field(default_factory=list)  # homoglyphs, zero-width characters


# --------------------------------------------------------------------------- v2 input hygiene and parsing helpers

_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad]")
_NUM_WORDS = {w: i for i, w in enumerate(
    ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"])}  # fmt: skip
_TENS = {
    w: 10 * (i + 2)
    for i, w in enumerate(["twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"])
}
_NUM_WORD_RE = re.compile(
    r"\b("
    + "|".join(_TENS)
    + r")(?:[- ]("
    + "|".join(list(_NUM_WORDS)[1:10])
    + r"))?\b|\b("
    + "|".join(_NUM_WORDS)
    + r")\b",
    re.I,
)
_TZ_OFFSETS = {"utc": 0, "gmt": 0, "z": 0, "est": -5, "edt": -4, "cst": -6, "cdt": -5, "mst": -7, "mdt": -6,
               "pst": -8, "pdt": -7, "bst": 1, "cet": 1, "cest": 2, "eet": 2, "eest": 3, "jst": 9, "aest": 10}  # fmt: skip
_AMBIGUOUS_TZ = {"ist", "ast", "cdt?"}
_TIME_RE = re.compile(
    r"(?<![\w:.])(?:(?P<date>\d{4}-\d{2}-\d{2})[T ])?(?P<h>[01]?\d|2[0-3]):(?P<m>[0-5]\d)(?::(?P<s>[0-5]\d))?"
    r"(?:\.\d+)?\s?(?P<tz>Z\b|UTC|GMT|[ECMP][SD]T|BST|CES?T|EES?T|JST|AEST|IST|AST|[+-]\d{2}:?\d{2})?(?![\w:])",
    re.I,
)
# Identifier-shaped names (host-like: letters, hyphen-separated, containing a digit), e.g. fin-db-07.
_IDENT_RE = re.compile(r"(?<![\w.\-])([a-z][a-z0-9]*(?:-[a-z0-9]+)+)(?![\w\-])", re.I)
_NOT_ENTITY_PREFIX = re.compile(
    r"^(?:cve|sha|md|utf|iso|rfc|tls|aes|rsa|kb|ms|t\d|x\d|e\d|d\d|evt|det|inv|win|ipv)", re.I
)


def words_to_digits(text: str) -> str:
    def sub(m: re.Match[str]) -> str:
        if m.group(3):
            return str(_NUM_WORDS[m.group(3).lower()])
        return str(_TENS[m.group(1).lower()] + (_NUM_WORDS[m.group(2).lower()] if m.group(2) else 0))

    return _NUM_WORD_RE.sub(sub, text)


def _script(ch: str) -> str:
    name = unicodedata.name(ch, "")
    return name.split(" ")[0] if ch.isalpha() else ""


def hygiene(text: str) -> tuple[str, list[str]]:
    """NFKC-normalise and report deceptive characters: zero-width/soft hyphens, and tokens mixing scripts
    (e.g. a Cyrillic 'а' inside 'alice'), which render identically to a real entity name but are not it."""
    issues = []
    if _ZERO_WIDTH.search(text):
        issues.append("invisible zero-width characters inside the text")
    norm = unicodedata.normalize("NFKC", text)
    for tok in re.findall(r"[^\s,;:()\[\]'\"]+", norm):
        scripts = {_script(c) for c in tok if c.isalpha()} - {""}
        if len(scripts) > 1:
            issues.append(
                f"token {tok!r} mixes {' and '.join(sorted(scripts)).lower()} letters (look-alike characters)"
            )
        elif scripts and scripts != {"LATIN"} and any(c.isascii() is False for c in tok):
            issues.append(f"token {tok!r} uses non-Latin letters that resemble Latin ones")
    return norm, issues


def parse_times(body: str) -> list[dict[str, Any]]:
    out = []
    for m in _TIME_RE.finditer(body):
        tz = (m["tz"] or "").lower()
        # A bare "10:20" needs context to be a time; require a date, a zone, or a preceding "at"/"around".
        if not (
            m["date"]
            or tz
            or re.search(r"\b(?:at|around|by|until|from|since)\s*$", body[max(0, m.start() - 8) : m.start()], re.I)
        ):
            continue
        if tz in ("ist", "ast"):
            out.append({"text": m.group(0), "ambiguous": True})
            continue
        if not tz:
            offset, assumed = 0.0, True
        elif tz[0] in "+-":
            sign = 1 if tz[0] == "+" else -1
            digits = tz[1:].replace(":", "")
            offset, assumed = sign * (int(digits[:2]) + int(digits[2:]) / 60), False
        else:
            offset, assumed = float(_TZ_OFFSETS.get(tz, 0)), False
        h, mi, sec = int(m["h"]), int(m["m"]), int(m["s"] or 0)
        utc_minutes = ((h * 60 + mi - int(offset * 60)) % 1440) + sec / 60
        utc = None
        if m["date"]:
            local = datetime.fromisoformat(f"{m['date']}T{h:02d}:{mi:02d}:{sec:02d}")
            utc = (local - timedelta(hours=offset)).replace(tzinfo=UTC)
        out.append({"text": m.group(0).strip(), "utc": utc, "minutes": utc_minutes, "assumed_utc": assumed,
                    "has_seconds": m["s"] is not None, "ambiguous": False})  # fmt: skip
    return out


def _split_names(blob: str) -> list[str]:
    parts = re.split(r",\s*and\s+|,\s*|\s+and\s+", blob)
    return [p.strip("'\"`.,;:()") for p in parts if p.strip("'\"`.,;:()")]


def _clean_token(tok: str) -> str:
    tok = tok.rstrip(".,;:!?)'\"")
    return tok[:-2] if tok.endswith("'s") else tok


def extract(text: str, scope: Scope) -> Assertions:
    text, a_deceptive = hygiene(text)
    a = Assertions(text=text, deceptive=a_deceptive)
    body = _ZERO_WIDTH.sub("", _REF_TOKENS.sub(" ", text))
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
    # v2: identifier-shaped names that appear without a "host"/"user" keyword (e.g. "reached fin-db-07").
    for m in _IDENT_RE.finditer(body):
        tok = _clean_token(m.group(1)).lower()
        if (any(ch.isdigit() for ch in tok) and not _NOT_ENTITY_PREFIX.match(tok) and tok not in scope.vocab_hosts
                and tok not in scope.vocab_users and not scope.entity_exists("host", tok)
                and not scope.entity_exists("user", tok) and f"host:{tok}" not in [x.lower() for x in a.unknown_entities]):  # fmt: skip
            a.unknown_entities.append(f"host:{tok}")

    # ---- activity mentions (with negation detected from the words just before each mention)
    neg_body = _QUANT_PHRASE.sub(lambda q: "_" * len(q.group(0)), body)  # "no more than" is not a negation
    for rx, label, types, outcome, keyword, external in _ACTIVITY_RE:
        for m in rx.finditer(body):
            before = neg_body[max(0, m.start() - 40) : m.start()]
            clause = re.split(_CLAUSE_BREAK, neg_body[: m.start()])[-1]
            negated = bool(_NEGATION_RE.search(before) or _CLAUSE_NEGATION_RE.search(clause))
            if any(abs(x.start - m.start()) < 3 and x.types == types for x in a.mentions):
                continue
            a.mentions.append(Mention(label, types, outcome, keyword, external, m.start(), negated))
    # "Every login attempt from X failed" is a universal claim: equivalent to "no successful login from X".
    for m in _UNIVERSAL_FAIL_RE.finditer(body):
        a.mentions = [
            x for x in a.mentions if not (x.types == frozenset({"auth.login"}) and m.start() <= x.start <= m.end())
        ]
        a.mentions.append(Mention("successful authentication", frozenset({"auth.login"}), "success", None, False,
                                  m.start(), True))  # fmt: skip
    a.mentions.sort(key=lambda x: x.start)
    # A specific mention (e.g. "PowerShell") subsumes a generic one ("executed") on the same type.
    specific = {t for x in a.mentions if x.keyword for t in x.types}
    a.mentions = [x for x in a.mentions if x.keyword or x.outcome or x.external_only or not (x.types & specific)]

    for m in _GAP_RE.finditer(body):
        word = next(g for g in m.groups() if g)
        a.gap_types.append(_TELEMETRY_WORDS[word.lower()])

    # ---- quantities ("forty-two" -> "42"; positions are not used after this point)
    qbody = words_to_digits(body)
    for rx, kind in ((_COUNT_FAILED, "failed_auth"), (_COUNT_HOSTS, "distinct_hosts"), (_COUNT_FLOWS, "flows"),
                     (_COUNT_SUCCESS, "success_auth")):  # fmt: skip
        for m in rx.finditer(qbody):
            a.counts.append(
                {"kind": kind, "n": int(m["n"].replace(",", "")), "qualifier": (m["q"] or "").strip().lower()}
            )
    for m in _COUNT_TIMES.finditer(qbody):
        times_n = {"once": 1, "twice": 2}[m["w"].lower()] if m["w"] else int(m["n"])
        if not any(c["kind"] == "success_auth" for c in a.counts):
            a.counts.append({"kind": "times", "n": times_n, "qualifier": (m["q"] or "").strip().lower()})
    for m in _VOLUME.finditer(qbody):
        mult = 1024**3 if m["u"].lower() in ("gb", "gib") else 1024**2
        a.counts.append({"kind": "bytes", "n": float(m["n"]) * mult, "qualifier": (m["q"] or "").strip().lower()})

    # ---- framing
    a.hedged = bool(_HEDGE_RE.search(lower))
    a.correlational = bool(_CORRELATION_RE.search(lower))
    a.dismissive = bool(_DISMISSIVE_RE.search(lower)) and not _REPORTED_SPEECH_RE.search(lower)
    a.times = parse_times(body)
    a.conclusions = sorted({m.group(0).lower() for m in _CONCLUSION_RE.finditer(body)})
    a.proof_language = bool(_PROOF_RE.search(lower))
    a.authority = bool(_AUTHORITY_RE.search(lower)) and not _REPORTED_SPEECH_RE.search(lower)
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
