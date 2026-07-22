from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Ubiquiti UniFi Network controller log (server.log). Logback layout is
# "[ts] <thread> LEVEL  logger - message":
#   [2026-06-28 10:15:01,123] <launcher> INFO  system - ======= UniFi started
#   [2026-06-28 10:15:02,234] <db-server> WARN  db.DBService - slow query 1200ms
#   [2026-06-28 10:15:03,345] <inform-12> ERROR api.StatusHandler - device adopt failed
# The "[ts] <thread> LEVEL  logger -" shape is the distinctive signature.
_PATTERN = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\] "
    r"<(?P<thread>[^>]*)> "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+"
    r"(?P<logger>\S+)"
    r"(?:\s+-\s+(?P<message>.*))?$"
)


class UnifiParser(LogParser):
    FORMAT_NAME = "unifi"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:25])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace(",", "."))
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="unifi",
            message=(m["message"] or "").strip(),
            raw=line,
            line_number=line_number,
            extra={
                "level": m["level"].lower(),
                "thread": m["thread"],
                "logger": m["logger"],
            },
        )
