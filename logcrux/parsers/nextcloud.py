from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Nextcloud server log (nextcloud.log) — one JSON object per line with a numeric
# level (0=debug … 4=fatal) and reqId/app fields:
#   {"reqId":"abc","level":1,"time":"2026-06-28T10:15:01+00:00","app":"core","message":"Login"}
#   {"reqId":"def","level":3,"time":"...","app":"files","method":"GET","url":"/","message":"error"}
# Detection keys off the reqId + numeric level + app trio, which no other
# JSON-per-line logger in the registry carries together.
_LEVEL_MAP = {
    0: Severity.DEBUG,
    1: Severity.INFO,
    2: Severity.WARNING,
    3: Severity.ERROR,
    4: Severity.CRITICAL,
}


def _parse_obj(line: str) -> dict[str, object] | None:
    line = line.strip()
    if not line.startswith("{") or "reqId" not in line:
        return None
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    if "reqId" in obj and "level" in obj and ("app" in obj or "message" in obj):
        return obj
    return None


class NextcloudParser(LogParser):
    FORMAT_NAME = "nextcloud"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_parse_obj(ln) is not None for ln in sample_lines[:25])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        obj = _parse_obj(line)
        if obj is None:
            return None
        ts = None
        if obj.get("time"):
            try:
                ts = dateparser.parse(str(obj["time"]))
            except (ValueError, TypeError, OverflowError):
                ts = None
        try:
            level = int(str(obj.get("level", 1)))
        except (ValueError, TypeError):
            level = 1
        raw_msg = obj.get("message", "")
        message = raw_msg if isinstance(raw_msg, str) else json.dumps(raw_msg)
        extra: dict[str, object] = {"level": level, "reqId": obj.get("reqId")}
        for key in ("app", "method", "url", "user", "userAgent"):
            if obj.get(key):
                extra[key] = obj[key]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(level, Severity.INFO),
            source="nextcloud",
            message=message.strip() or f"{obj.get('app', '')} event",
            raw=line,
            line_number=line_number,
            extra=extra,
        )
