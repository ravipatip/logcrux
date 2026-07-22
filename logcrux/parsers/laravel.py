from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Laravel / Monolog application log (storage/logs/laravel.log). Layout is
# "[ts] env.LEVEL: message {context}":
#   [2026-06-28 10:15:01] production.INFO: User logged in {"id":42}
#   [2026-06-28 10:15:02] production.WARNING: Slow query detected
#   [2026-06-28 10:15:03] production.ERROR: SQLSTATE[HY000] connection refused
# The "[ts] <env>.<LEVEL>:" shape is the distinctive Monolog signature.
_PATTERN = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?)\] "
    r"(?P<env>[\w-]+)\."
    r"(?P<level>DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY): "
    r"(?P<message>.*)$"
)


class LaravelParser(LogParser):
    FORMAT_NAME = "laravel"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:25])

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
            source="laravel",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"env": m["env"], "level": m["level"].lower()},
        )
