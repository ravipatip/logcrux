from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Django development server (runserver) request log:
#   [20/Jun/2026 10:15:01] "GET /api/ HTTP/1.1" 200 1234
#   [20/Jun/2026 10:15:01] "GET /missing HTTP/1.1" 404 179
# and the server-control lines it interleaves:
#   [20/Jun/2026 10:15:01] code 400, message Bad request syntax
# Distinct from Werkzeug by the *leading* "[date time]" (no client IP prefix).
_ACCESS = re.compile(
    r'^\[(?P<ts>\d{2}/\w{3}/\d{4} \d{2}:\d{2}:\d{2})\] '
    r'"(?P<method>\w+) (?P<path>[^"]*) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)
_CONTROL = re.compile(
    r'^\[(?P<ts>\d{2}/\w{3}/\d{4} \d{2}:\d{2}:\d{2})\] (?P<message>.+)$'
)


class DjangoParser(LogParser):
    FORMAT_NAME = "django"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _ACCESS.match(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _ACCESS.match(line)
        if m:
            try:
                ts = dateparser.parse(m["ts"].replace("/", " "), dayfirst=True)
            except (ValueError, TypeError, OverflowError):
                ts = None
            status = int(m["status"])
            if status >= 500:
                severity = Severity.ERROR
            elif status >= 400:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO
            return ParsedEvent(
                timestamp=ts,
                severity=severity,
                source="django",
                message=f'{m["method"]} {m["path"]} -> {status}',
                raw=line,
                line_number=line_number,
                extra={"method": m["method"], "path": m["path"], "status": status},
            )
        c = _CONTROL.match(line)
        if not c:
            return None
        try:
            ts = dateparser.parse(c["ts"].replace("/", " "), dayfirst=True)
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = c["message"].strip()
        low = message.lower()
        severity = Severity.WARNING if low.startswith("code ") or "error" in low else Severity.INFO
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="django",
            message=message,
            raw=line,
            line_number=line_number,
            extra={},
        )
