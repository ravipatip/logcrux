from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Ruby on Rails development/production request log. Rails emits a recognizable
# sequence of lines per request:
#   Started GET "/users/1" for 127.0.0.1 at 2026-06-20 10:15:01 +0000
#   Processing by UsersController#show as HTML
#   Completed 200 OK in 15ms (Views: 10.2ms | ActiveRecord: 2.1ms)
#   Completed 500 Internal Server Error in 8ms
# (optionally prefixed with a "[request-id] " tag).
_STARTED = re.compile(
    r'^(?:\[[\w-]+\] )?Started (?P<method>\w+) "(?P<path>[^"]*)" for (?P<client>\S+) '
    r'at (?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
)
_COMPLETED = re.compile(
    r'^(?:\[[\w-]+\] )?Completed (?P<status>\d{3}) (?P<text>[^()]+?) in (?P<ms>[\d.]+)ms'
)
_MARKER = re.compile(
    r'^(?:\[[\w-]+\] )?(Started \w+ "|Processing by |Completed \d{3} |Rendered |'
    r'Parameters: |Redirected to )'
)


class RailsParser(LogParser):
    FORMAT_NAME = "rails"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _STARTED.match(ln) or _COMPLETED.match(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        s = _STARTED.match(line)
        if s:
            try:
                ts = dateparser.parse(s["ts"])
            except (ValueError, TypeError, OverflowError):
                ts = None
            return ParsedEvent(
                timestamp=ts,
                severity=Severity.INFO,
                source="rails",
                message=f'Started {s["method"]} {s["path"]}',
                raw=line,
                line_number=line_number,
                extra={"method": s["method"], "path": s["path"], "client": s["client"]},
            )
        c = _COMPLETED.match(line)
        if c:
            status = int(c["status"])
            if status >= 500:
                severity = Severity.ERROR
            elif status >= 400:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO
            return ParsedEvent(
                timestamp=None,
                severity=severity,
                source="rails",
                message=f'Completed {status} {c["text"].strip()} in {c["ms"]}ms',
                raw=line,
                line_number=line_number,
                extra={"status": status, "duration_ms": float(c["ms"])},
            )
        if not _MARKER.match(line):
            return None
        return ParsedEvent(
            timestamp=None,
            severity=Severity.INFO,
            source="rails",
            message=line.strip(),
            raw=line,
            line_number=line_number,
            extra={},
        )
