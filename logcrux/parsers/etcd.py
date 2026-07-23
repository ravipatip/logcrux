from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# etcd (zap JSON logger) emits one JSON object per line:
#   {"level":"warn","ts":"2026-06-20T10:23:45.123Z","caller":"etcdserver/util.go:163",
#    "msg":"apply request took too long","took":"200ms","expected-duration":"100ms"}
# The distinguishing keys are "caller" + "ts" + "msg" (zap's default encoder).
_LEVEL_MAP: dict[str, Severity] = {
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "dpanic": Severity.CRITICAL,
    "panic": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
}


def _is_etcd_json(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "caller" in obj
        and "ts" in obj
        and "msg" in obj
        and "level" in obj
    )


class EtcdParser(LogParser):
    FORMAT_NAME = "etcd"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "etcd" in str(path).lower():
            return True
        for line in sample_lines[:10]:
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            if _is_etcd_json(obj):
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
        if isinstance(ts_raw, str):
            try:
                ts = dateparser.parse(ts_raw)
            except (ValueError, TypeError, OverflowError):
                ts = None
        level = str(obj.get("level", "info")).lower()
        message = str(obj.get("msg", ""))
        extra: dict[str, object] = {"level": level}
        if "caller" in obj:
            extra["caller"] = obj["caller"]
        # Surface the most useful structured attributes for context.
        for key in ("error", "took", "to", "from", "member", "remote-peer-id"):
            if key in obj:
                extra[key] = obj[key]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(level, Severity.INFO),
            source="etcd",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
