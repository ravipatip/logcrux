from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable

from logcrux.models import ParsedEvent, Subject

# What a finding is *about*. "Authentication failure cluster (144 events)" is
# not actionable; "from 203.0.113.9 (140), users root (40), admin (31)" is —
# it is the line an operator otherwise greps for. Each extractor reads one
# event and yields (label, value) pairs; counts are taken over every event the
# detector matched, not just the representative sample.

# IPv6 needs "::" or at least four groups, or "18:47:22" reads as an address.
_IP = (r"(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}"
       r"|[0-9a-fA-F]{0,4}::[0-9a-fA-F:]*[0-9a-fA-F])")

# sshd / pam / postgres / mariadb / sudo wordings, all from real captures.
_AUTH_SOURCE_RE = re.compile(
    rf"(?:\bfrom\s+\[?|\brhost=|@'|\bclient=|\bhost=\[?|\bconnection from\s+\[?"
    rf"|\bipAddress=\"|\bIP=|\bclient:\s*)({_IP})\b"
)
_AUTH_USER_RES = (
    re.compile(r"\bfor (?:invalid user |illegal user )?(?!user\b)([\w.@$-]+) from\b"),
    re.compile(r"\binvalid user ([\w.@$-]+)"),
    re.compile(r"\bfor user \"([^\"]+)\""),                    # postgres
    re.compile(r"\bfor user '?([\w.@$-]+)'?(?=[\s,;:)]|$)"),   # "for user bob from ..."
    re.compile(r"\bAccess denied for user '([^']+)'"),          # mariadb/mysql
    re.compile(r"(?:^|;\s*|\s)user=([\w.@$-]+)"),               # pam
    re.compile(r"^\s*([\w.@$-]+) : (?:\d+ incorrect password|user NOT in sudoers)"),  # sudo
    re.compile(r"\busername=\"([^\"]+)\""),                    # keycloak
    re.compile(r"\bAuthentication for user \[([^\]]+)\]"),        # samba
    re.compile(r"\buser \"([^\"]+)\": password mismatch"),          # nginx auth_basic
)
_PHP_SCRIPT_RE = re.compile(r"\bin (/\S+\.php):\d+")

_OOM_VICTIM_RE = re.compile(r"Killed process \d+ \(([^)]+)\)")
_OOM_TASK_RE = re.compile(r"\btask=([^,\s]+)")
_OOM_CGROUP_RE = re.compile(r"oom_memcg=([^,\s]+)")

_UNIT_RE = re.compile(r"\b([\w@.\\:-]+\.(?:service|scope|socket|timer|mount))\b")
_SEGFAULT_RE = re.compile(r"\b([\w.+-]+)\[\d+\]: segfault\b")
_PG_BACKEND_RE = re.compile(
    r"\b(server process|client backend|\w+ worker) \(PID \d+\) was terminated by (\w+ \d+)"
)
_POD_RE = re.compile(r"\bpod/([\w.-]+)|\bpod[=\s]\"?([\w./-]+?)(?:_[\w-]+)?[\"(\s]")
_DEVICE_RE = re.compile(r"\b(?:on dev(?:ice)?|device)\s+\(?([\w/.-]+?)\)?[,:\s]")


def _auth(e: ParsedEvent) -> Iterable[tuple[str, str]]:
    msg = e.message
    ip = e.extra.get("client_ip") or e.extra.get("src_ip")
    if ip:
        yield "source", str(ip)
    else:
        m = _AUTH_SOURCE_RE.search(msg)
        if m:
            yield "source", m[1]
    for rx in _AUTH_USER_RES:
        m = rx.search(msg)
        if m:
            yield "user", m[1]
            break


def _oom(e: ParsedEvent) -> Iterable[tuple[str, str]]:
    m = _OOM_VICTIM_RE.search(e.message) or _OOM_TASK_RE.search(e.message)
    if m:
        yield "killed", m[1]
    m = _OOM_CGROUP_RE.search(e.message)
    if m and m[1] not in ("/", ""):
        yield "cgroup", m[1]


def _crash(e: ParsedEvent) -> Iterable[tuple[str, str]]:
    msg = e.message
    m = _OOM_VICTIM_RE.search(msg)
    if m:
        yield "process", m[1]
        return
    m = _SEGFAULT_RE.search(msg)
    if m:
        yield "process", m[1]
        return
    m = _PG_BACKEND_RE.search(msg)
    if m:
        yield "process", f"postgres {m[1]} ({m[2]})"
        return
    m = _PHP_SCRIPT_RE.search(msg)
    if m and "PHP Fatal error" in msg:
        yield "script", m[1]
        return
    m = _UNIT_RE.search(msg)
    if m:
        yield "unit", m[1]
        return
    m = _POD_RE.search(msg)
    if m:
        yield "pod", m[1] or m[2]
        return
    if e.source and e.source not in ("generic", "kernel", "systemd"):
        yield "service", e.source


def _disk(e: ParsedEvent) -> Iterable[tuple[str, str]]:
    m = _DEVICE_RE.search(e.message + " ")
    if m:
        yield "device", m[1]
    elif e.source and e.source != "generic":
        yield "service", e.source


def _http(e: ParsedEvent) -> Iterable[tuple[str, str]]:
    status = e.extra.get("status_code") or e.extra.get("status")
    if status is not None:
        yield "status", str(status)
    path = e.extra.get("path")
    if path:
        yield "path", str(path).split("?", 1)[0]
    ip = e.extra.get("client_ip")
    if ip:
        yield "client", str(ip)


_BACKEND_SERVER_RE = re.compile(r"\bServer (\S+/\S+) is DOWN|\bbackend '?([^'\s]+?)'? has no")


def _backend(e: ParsedEvent) -> Iterable[tuple[str, str]]:
    m = _BACKEND_SERVER_RE.search(e.message)
    if m and m[1]:
        yield "server", m[1]
    elif m:
        yield "backend", m[2]


_IMAGE_RE = re.compile(r"(?:image \\?\"|Image:)([\w./:@-]+)")
_DIRECTIVE_RE = re.compile(r"unknown directive \"([^\"]+)\" in (\S+)")


def _config(e: ParsedEvent) -> Iterable[tuple[str, str]]:
    m = _DIRECTIVE_RE.search(e.message)
    if m:
        yield "directive", f"{m[1]} ({m[2]})"
        return
    m = _IMAGE_RE.search(e.message)
    if m:
        yield "image", m[1]
    pod = _POD_RE.search(e.message)
    if pod:
        yield "pod", pod[1] or pod[2]


_MAIL_CLIENT_RE = re.compile(r"\bRCPT from (\S+?\[[^\]]+\])")
_MAIL_REASON_RE = re.compile(r"\d{3} \d\.\d\.\d+ (?:<[^>]*>: )?([^;]+)")


def _mail(e: ParsedEvent) -> Iterable[tuple[str, str]]:
    m = _MAIL_CLIENT_RE.search(e.message)
    if m:
        yield "client", m[1]
    m = _MAIL_REASON_RE.search(e.message)
    if m:
        yield "reason", m[1].strip()


def _limit(e: ParsedEvent) -> Iterable[tuple[str, str]]:
    from logcrux.analysis.anomaly import resource_limit_kind
    kind = resource_limit_kind(e)
    if kind:
        yield "limit", kind
    if e.source and e.source not in ("generic", "unknown"):
        yield "service", e.source


def _clock(e: ParsedEvent) -> Iterable[tuple[str, str]]:
    from logcrux.analysis.anomaly import clock_offset
    off = clock_offset(e)
    if off is not None:
        yield "offset", f"{off:+.0f} s"


_EXTRACTORS: dict[str, Callable[[ParsedEvent], Iterable[tuple[str, str]]]] = {
    "auth_failure_cluster": _auth,
    "oom_event": _oom,
    "service_crash": _crash,
    "disk_full": _disk,
    "backend_down": _backend,
    "config_error": _config,
    "mail_reject_cluster": _mail,
    "resource_limit": _limit,
    "clock_jump": _clock,
}

# Masking for message templates: numbers, hex ids, IPs, quoted values and
# paths vary per line; the shape that stays is what the operator recognises.
_MASKS = (
    (re.compile(r"\d{4}-\d\d-\d\d[T ]\s?\d{1,2}:\d\d:\d\d(?:[.,]\d+)?"
                r"(?:Z|[+-]\d\d:?\d\d)?"), "<ts>"),
    (re.compile(r"\b\d{1,2}:\d\d:\d\d(?:[.,]\d+)?\b"), "<time>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(rf"\b{_IP}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{12,}\b"), "<hex>"),
    (re.compile(r"\d+(?:\.\d+)?"), "<n>"),
)


def template(message: str) -> str:
    """The message's first line with variable tokens masked."""
    first = message.split("\n", 1)[0].strip()
    for rx, repl in _MASKS:
        first = rx.sub(repl, first)
    return " ".join(first.split())[:200]


def top_templates(events: Iterable[ParsedEvent], limit: int = 3) -> list[Subject]:
    counts = Counter(template(e.message) for e in events)
    return [Subject(label="message", value=v, count=n) for v, n in counts.most_common(limit) if v]


def subjects(kind: str, events: list[ParsedEvent], limit: int = 3) -> list[Subject]:
    """Top subjects of a signal: who/what the matched events are about.

    Signals with no specific extractor (error bursts, rate spikes, job and
    storage faults) report their most frequent message templates instead, so
    a burst of 4,000 errors says *which* error it is.
    """
    if not events:
        return []
    is_http = any("status_code" in e.extra or "status" in e.extra for e in events[:50])
    extractor = _EXTRACTORS.get(kind) or (_http if is_http else None)
    if extractor is None:
        return top_templates(events, limit)
    by_label: dict[str, Counter[str]] = {}
    for e in events:
        for label, value in extractor(e):
            by_label.setdefault(label, Counter())[value] += 1
    # "service: postgresql" next to "process: postgres server process" says
    # nothing new; the parser's source is only a fallback subject.
    if len(by_label) > 1:
        by_label.pop("service", None)
    out: list[Subject] = []
    for label, counter in by_label.items():
        out += [Subject(label=label, value=v, count=n) for v, n in counter.most_common(limit)]
    return out or top_templates(events, limit)


# The single most telling line per kind, guaranteed a place in the evidence
# when present: frequency alone picked two systemd lines for a kernel OOM kill.
_DECISIVE = {
    "oom_event": re.compile(r"Killed process \d+ \(|Out of memory: |OutOfMemoryError"),
    "service_crash": re.compile(
        r"segfault at|terminated by signal|Main process exited|crashed by signal"
    ),
    "auth_failure_cluster": re.compile(r"Failed password|Invalid user|authentication failed", re.I),
}


def decisive_first(kind: str, events: list[ParsedEvent], limit: int = 3) -> list[ParsedEvent]:
    picked = evidence_events(events, limit)
    rx = _DECISIVE.get(kind)
    if rx is None or any(rx.search(e.message) for e in picked):
        return picked
    hit = next((e for e in events if rx.search(e.message)), None)
    if hit is None:
        return picked
    return sorted([hit, *picked[: limit - 1]], key=lambda e: e.line_number)


def evidence_events(events: list[ParsedEvent], limit: int = 3) -> list[ParsedEvent]:
    """Pick up to ``limit`` events, one per message template, most frequent
    template first, returned in file order — so three identical "Failed
    password" lines don't crowd out the line that explains the incident, and
    the lines shown are the ones the incident mostly consists of."""
    first: dict[str, ParsedEvent] = {}
    counts: Counter[str] = Counter()
    for e in events:
        t = template(e.message)
        counts[t] += 1
        first.setdefault(t, e)
    # Ties go to the shorter template: "Failed password for root from <ip>"
    # says more at a glance than PAM's long "authentication failure; logname=...".
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], len(kv[0])))
    picked = [first[t] for t, _ in ranked[:limit]]
    return sorted(picked, key=lambda e: e.line_number)
