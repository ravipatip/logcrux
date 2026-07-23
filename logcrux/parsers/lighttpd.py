from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# lighttpd error log. Each line is "YYYY-MM-DD HH:MM:SS: (source.c.line) msg":
#   2026-06-28 10:15:01: (server.c.1558) server started (lighttpd/1.4.69)
#   2026-06-28 10:15:02: (mod_fastcgi.c.421) FastCGI-stderr: PHP Fatal error
#   2026-06-28 10:15:03: (connections.c.999) connection closed: timeout
# The " : (file.c.NNN) " token is the distinctive signature.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}): "
    r"\((?P<src>[\w.-]+\.c\.\d+)\) "
    r"(?P<message>.*)$"
)
_ERROR_MARKERS = ("error", "failed", "can't", "cannot", "unable", "fatal",
                  "denied", "refused", "no such", "couldn't", "aborted")
_WARN_MARKERS = ("warning", "timeout", "timed out", "overload", "disabled",
                 "retry", "deprecat", "closed: ", "premature")


def _severity(message: str) -> Severity:
    low = message.lower()
    if any(m in low for m in _ERROR_MARKERS):
        return Severity.ERROR
    if any(m in low for m in _WARN_MARKERS):
        return Severity.WARNING
    return Severity.INFO


class LighttpdParser(LogParser):
    FORMAT_NAME = "lighttpd"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(m["message"]),
            source="lighttpd",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"src": m["src"]},
        )
