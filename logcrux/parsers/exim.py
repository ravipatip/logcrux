from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Exim mainlog / rejectlog format:
#   2024-06-20 10:23:45 1abcde-0001AB-2C <= sender@a.com H=mail.a.com [1.2.3.4] P=esmtp S=1234
#   2024-06-20 10:23:45 1abcde-0001AB-2C => user@b.com R=dnslookup T=remote_smtp
#   2024-06-20 10:23:45 1abcde-0001AB-2C ** user@b.com: retry timeout exceeded
#   2024-06-20 10:23:45 1abcde-0001AB-2C == user@b.com R=dnslookup defer (-44): SMTP timeout
#   2024-06-20 10:23:45 H=(spam) [5.6.7.8] F=<x@y> rejected RCPT <z@a.com>: relay not permitted
_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?:(?P<msgid>\w{6}-\w{6}-\w{2}) )?"
    r"(?P<flag><=|=>|->|>>|\*>|\*\*|==)?\s*"
    r"(?P<message>.*)"
)

_MSGID_RE = re.compile(r"\b\w{6}-\w{6}-\w{2}\b")

# Flag → severity. "**" = delivery failure/bounce, "==" = deferred (retry).
_FLAG_SEVERITY: dict[str, Severity] = {
    "<=": Severity.INFO,   # message arrival
    "=>": Severity.INFO,   # successful delivery
    "->": Severity.INFO,   # additional address delivered
    ">>": Severity.INFO,   # cutthrough delivery
    "*>": Severity.INFO,   # delivery suppressed (-N)
    "**": Severity.ERROR,  # delivery failed (bounce)
    "==": Severity.WARNING,  # delivery deferred
}

_ERROR_KEYWORDS = frozenset([
    "rejected", "refused", "fatal", "frozen", "cannot", "unable",
    "no such", "timeout", "fixed_login", "authenticator failed",
])


def _exim_severity(flag: str | None, message: str) -> Severity:
    if flag and flag in _FLAG_SEVERITY:
        sev = _FLAG_SEVERITY[flag]
        if sev != Severity.INFO:
            return sev
    low = message.lower()
    if "rejected" in low or "authenticator failed" in low or "frozen" in low:
        return Severity.WARNING
    if any(kw in low for kw in _ERROR_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class EximParser(LogParser):
    FORMAT_NAME = "exim"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        name = path.name.lower() if path else ""
        if "exim" in name or name in ("mainlog", "rejectlog", "paniclog"):
            return True
        # Require an Exim message-id or a delivery flag to avoid claiming other
        # "YYYY-MM-DD HH:MM:SS" logs (kafka/rabbitmq/gunicorn use brackets).
        hits = 0
        for line in sample_lines[:10]:
            m = _PATTERN.match(line)
            if not m:
                continue
            if m["msgid"] or m["flag"] in ("<=", "=>", "**", "=="):
                hits += 1
        return hits > 0

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        # Reject plain "date message" lines with neither msgid nor flag unless
        # they carry an Exim keyword, so we don't swallow unrelated logs.
        flag = m["flag"]
        message = m["message"].strip()
        if not m["msgid"] and not flag and not any(
            kw in message.lower() for kw in _ERROR_KEYWORDS
        ):
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        extra: dict[str, object] = {}
        if m["msgid"]:
            extra["msg_id"] = m["msgid"]
        if flag:
            extra["flag"] = flag
        return ParsedEvent(
            timestamp=ts,
            severity=_exim_severity(flag, message),
            source="exim",
            message=(f"{flag} {message}".strip() if flag else message),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
