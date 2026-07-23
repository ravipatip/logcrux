from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Traefik default (zerolog) JSON: one object per line, with "level"+"message"
# (or "msg") and an RFC3339 string "time" key:
#   {"level":"error","error":"...","time":"2026-06-20T10:23:45Z",
#    "message":"Error while creating client"}
# Distinguished from caddy/etcd by the string "time" key + no "ts"/"caller".
_LEVEL_MAP: dict[str, Severity] = {
    "trace": Severity.DEBUG,
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "fatal": Severity.CRITICAL,
    "panic": Severity.CRITICAL,
}


def _is_traefik_json(obj: object) -> bool:
    if not isinstance(obj, dict):
        return False
    has_msg = "message" in obj or "msg" in obj
    return (
        has_msg
        and "level" in obj
        and "time" in obj
        and isinstance(obj.get("time"), str)
        and "ts" not in obj
        and "caller" not in obj
        and "logger" not in obj
    )


class TraefikParser(LogParser):
    FORMAT_NAME = "traefik"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "traefik" in str(path).lower():
            return True
        for line in sample_lines[:10]:
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            if _is_traefik_json(obj):
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
        if not isinstance(obj, dict):
            return None
        message = obj.get("message") or obj.get("msg")
        if message is None:
            return None
        ts = None
        ts_raw = obj.get("time")
        if isinstance(ts_raw, str):
            try:
                ts = dateparser.parse(ts_raw)
            except (ValueError, TypeError, OverflowError):
                ts = None
        level = str(obj.get("level", "info")).lower()
        extra: dict[str, object] = {"level": level}
        for key in ("error", "entryPointName", "routerName", "serviceName"):
            if key in obj:
                extra[key] = obj[key]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(level, Severity.INFO),
            source="traefik",
            message=str(message),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
