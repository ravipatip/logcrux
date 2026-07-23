from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Trino / PrestoSQL distributed-SQL engine logs (airlift framework). Layout is
# "ISO-ts LEVEL thread logger message" (tab- or space-separated):
#   2026-06-28T10:15:01.123+0000 INFO main io.trino.server.Server ======= STARTING
#   2026-06-28T10:15:02.234+0000 WARN page-buffer io.trino.execution.SqlTask Slow
#   2026-06-28T10:15:03.345+0000 ERROR query-1 io.trino.execution.QueryStateMachine Failed
# The "ISO-ts LEVEL <thread> io.trino/io.prestosql logger" shape is the signature.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(?:[+-]\d{4})?)\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+"
    r"(?P<thread>\S+)\s+"
    r"(?P<logger>\S+)\s+"
    r"(?P<message>.*)$"
)
_MARKERS = ("io.trino", "io.prestosql", "com.facebook.presto", "trino", "presto")


class TrinoParser(LogParser):
    FORMAT_NAME = "trino"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:25] if _PATTERN.match(ln)]
        if not matched:
            return False
        return any(mk in ln for ln in matched for mk in _MARKERS)

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
            severity=level_to_severity(m["level"]),
            source="trino",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={
                "level": m["level"].lower(),
                "thread": m["thread"],
                "logger": m["logger"],
            },
        )
