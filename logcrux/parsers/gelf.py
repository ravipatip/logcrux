from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Graylog Extended Log Format (GELF) — one JSON object per line, widely emitted
# by app frameworks shipping to Graylog:
#   {"version":"1.1","host":"web01","short_message":"login failed",
#    "timestamp":1718880225.123,"level":3,"_user":"bob"}
# Distinguished by version "1.1" + short_message + host. "level" is the syslog
# numeric severity (0=emerg .. 7=debug).
_SYSLOG_NUM = {
    0: Severity.CRITICAL,
    1: Severity.CRITICAL,
    2: Severity.CRITICAL,
    3: Severity.ERROR,
    4: Severity.WARNING,
    5: Severity.INFO,
    6: Severity.INFO,
    7: Severity.DEBUG,
}


def _is_gelf(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and str(obj.get("version", "")).startswith("1.")
        and "short_message" in obj
        and "host" in obj
    )


class GELFParser(LogParser):
    FORMAT_NAME = "gelf"

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
            if _is_gelf(obj):
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
        if not _is_gelf(obj):
            return None
        ts = None
        ts_raw = obj.get("timestamp")
        if isinstance(ts_raw, (int, float)):
            try:
                ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                ts = None
        level = obj.get("level")
        severity = (
            _SYSLOG_NUM.get(level, Severity.INFO) if isinstance(level, int) else Severity.INFO
        )
        message = str(obj.get("short_message", ""))
        extra: dict[str, object] = {"host": obj.get("host"), "level": level}
        # Surface a few custom "_"-prefixed fields (GELF additional fields).
        for k, v in obj.items():
            if k.startswith("_") and len(extra) < 8:
                extra[k.lstrip("_")] = v
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=str(obj.get("host", "gelf")),
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
