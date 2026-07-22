from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Pino (Node.js structured logger) emits one JSON object per line with a
# *numeric* level and an epoch-millisecond "time":
#   {"level":30,"time":1718877301123,"pid":12,"hostname":"h","msg":"listening"}
# Numeric levels: 10 trace, 20 debug, 30 info, 40 warn, 50 error, 60 fatal.
_NUM_LEVEL: dict[int, Severity] = {
    10: Severity.DEBUG,
    20: Severity.DEBUG,
    30: Severity.INFO,
    40: Severity.WARNING,
    50: Severity.ERROR,
    60: Severity.CRITICAL,
}


def _is_pino(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("level"), int)
        and isinstance(obj.get("time"), int)
        and "msg" in obj
        and "v" not in obj  # bunyan carries "v":0 — let it win
    )


class PinoParser(LogParser):
    FORMAT_NAME = "pino"

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
            if _is_pino(obj):
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
        if not isinstance(obj, dict) or "msg" not in obj or not isinstance(
            obj.get("level"), int
        ):
            return None
        ts = None
        time_raw = obj.get("time")
        if isinstance(time_raw, int):
            try:
                ts = datetime.fromtimestamp(time_raw / 1000.0, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                ts = None
        level = int(obj["level"])
        extra: dict[str, object] = {"level": level}
        for key in ("pid", "hostname", "name", "reqId", "req", "err"):
            if key in obj:
                extra[key] = obj[key]
        return ParsedEvent(
            timestamp=ts,
            severity=_NUM_LEVEL.get(level, Severity.INFO),
            source=str(obj.get("name", "pino")),
            message=str(obj.get("msg", "")),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
