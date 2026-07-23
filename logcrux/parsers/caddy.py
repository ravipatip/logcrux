from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Caddy v2 (zap JSON) logs one object per line, with a "logger" name, a numeric
# epoch "ts" and "msg":
#   {"level":"error","ts":1718880225.123,"logger":"http.log.access",
#    "msg":"handled request","request":{"method":"GET","uri":"/"},"status":502}
# Distinguished from etcd (which uses "caller") by the "logger" key.
_LEVEL_MAP: dict[str, Severity] = {
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "panic": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
}


def _is_caddy_json(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "logger" in obj
        and "ts" in obj
        and "msg" in obj
        and "level" in obj
    )


class CaddyParser(LogParser):
    FORMAT_NAME = "caddy"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "caddy" in str(path).lower():
            return True
        for line in sample_lines[:10]:
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            if _is_caddy_json(obj):
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
        if not isinstance(obj, dict) or "msg" not in obj:
            return None
        ts = None
        ts_raw = obj.get("ts")
        if isinstance(ts_raw, (int, float)):
            try:
                ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                ts = None
        level = str(obj.get("level", "info")).lower()
        message = str(obj.get("msg", ""))
        extra: dict[str, object] = {"level": level, "logger": obj.get("logger")}
        # Access-log lines carry a nested request + status — surface them.
        req = obj.get("request")
        if isinstance(req, dict):
            if "method" in req:
                extra["method"] = req["method"]
            if "uri" in req:
                extra["uri"] = req["uri"]
        if "status" in obj:
            extra["status"] = obj["status"]
        if "error" in obj:
            extra["error"] = obj["error"]
        # Elevate a 5xx access-log line so overload/backends surface as errors.
        status = obj.get("status")
        severity = _LEVEL_MAP.get(level, Severity.INFO)
        if isinstance(status, int) and status >= 500 and severity == Severity.INFO:
            severity = Severity.ERROR
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="caddy",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
