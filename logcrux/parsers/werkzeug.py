from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Werkzeug / Flask development server access line:
#   127.0.0.1 - - [20/Jun/2026 10:15:01] "GET /api HTTP/1.1" 200 -
# Distinct from Apache/CLF: a *space* (not a colon) separates date and time and
# there is no timezone offset inside the brackets.
_PATTERN = re.compile(
    r'^(?P<client>\S+) - - '
    r'\[(?P<ts>\d{2}/\w{3}/\d{4} \d{2}:\d{2}:\d{2})\] '
    r'"(?P<method>\w+) (?P<path>[^"]*) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)


class WerkzeugParser(LogParser):
    FORMAT_NAME = "werkzeug"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _PATTERN.match(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts: datetime | None = dateparser.parse(
                m["ts"].replace("/", " "), dayfirst=True
            )
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
            source="werkzeug",
            message=f'{m["method"]} {m["path"]} -> {status}',
            raw=line,
            line_number=line_number,
            extra={
                "client": m["client"],
                "method": m["method"],
                "path": m["path"],
                "status": status,
            },
        )
