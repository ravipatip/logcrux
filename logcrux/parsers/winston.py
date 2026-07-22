from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# Winston (Node.js logger, JSON format) emits one object per line with a
# *string* level plus "message" and "timestamp":
#   {"level":"info","message":"server started","timestamp":"2026-06-20T10:15:01.123Z"}
# This is a deliberately broad shape, so it is checked late (after the more
# specific JSON loggers) and requires all three string fields to claim a line.


def _is_winston(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("level"), str)
        and "message" in obj
        and "timestamp" in obj
        # don't poach Azure activity logs (operationName) or k8s audit (kind)
        and "operationName" not in obj
        and "kind" not in obj
    )


class WinstonParser(LogParser):
    FORMAT_NAME = "winston"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for line in sample_lines[:10]:
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            if _is_winston(obj):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        stripped = line.strip()
        if not stripped.startswith("{"):
            return None
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return None
        if not _is_winston(obj):
            return None
        ts = None
        t_raw = obj.get("timestamp")
        if isinstance(t_raw, str):
            try:
                ts = dateparser.parse(t_raw)
            except (ValueError, TypeError, OverflowError):
                ts = None
        level = str(obj.get("level", "info"))
        severity = level_to_severity(level)
        if obj.get("stack") and severity.value in ("info", "debug"):
            severity = Severity.ERROR
        extra: dict[str, object] = {"level": level.lower()}
        for key in ("service", "label", "requestId", "stack"):
            if key in obj:
                extra[key] = obj[key]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=str(obj.get("service", "winston")),
            message=str(obj.get("message", "")),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
