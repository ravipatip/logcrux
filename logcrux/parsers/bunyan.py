from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Bunyan (Node.js logger) emits one JSON object per line carrying the
# signature fields name/hostname/pid/level/msg/time and the schema marker
# "v":0:
#   {"name":"app","hostname":"h","pid":1,"level":30,"msg":"up",
#    "time":"2026-06-20T10:15:01.123Z","v":0}
# Numeric levels: 10 trace, 20 debug, 30 info, 40 warn, 50 error, 60 fatal.
_NUM_LEVEL: dict[int, Severity] = {
    10: Severity.DEBUG,
    20: Severity.DEBUG,
    30: Severity.INFO,
    40: Severity.WARNING,
    50: Severity.ERROR,
    60: Severity.CRITICAL,
}


def _is_bunyan(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and obj.get("v") == 0
        and "name" in obj
        and isinstance(obj.get("level"), int)
        and "msg" in obj
        and "time" in obj
    )


class BunyanParser(LogParser):
    FORMAT_NAME = "bunyan"

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
            if _is_bunyan(obj):
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
        if not _is_bunyan(obj):
            return None
        ts = None
        time_raw = obj.get("time")
        if isinstance(time_raw, str):
            try:
                ts = dateparser.parse(time_raw)
            except (ValueError, TypeError, OverflowError):
                ts = None
        level = int(obj["level"])
        extra: dict[str, object] = {"level": level, "pid": obj.get("pid")}
        for key in ("hostname", "component", "req_id", "err"):
            if key in obj:
                extra[key] = obj[key]
        return ParsedEvent(
            timestamp=ts,
            severity=_NUM_LEVEL.get(level, Severity.INFO),
            source=str(obj.get("name", "bunyan")),
            message=str(obj.get("msg", "")),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
