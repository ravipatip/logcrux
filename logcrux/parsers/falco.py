from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Falco runtime-security engine (CNCF) — JSON output, one alert per line:
#   {"hostname":"node1","output":"File below /etc opened for writing ...",
#    "priority":"Warning","rule":"Write below etc","source":"syscall",
#    "tags":["filesystem"],"time":"2026-06-28T10:15:01.123456789Z",
#    "output_fields":{"proc.name":"vi","user.name":"root"}}
# Distinguished by the priority + rule + output triad.
_PRIORITY = {
    "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "notice": Severity.INFO,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "debug": Severity.DEBUG,
}


def _is_falco(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "priority" in obj
        and "rule" in obj
        and "output" in obj
    )


class FalcoParser(LogParser):
    FORMAT_NAME = "falco"

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
            if _is_falco(obj):
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
        if not _is_falco(obj):
            return None
        ts = None
        raw_ts = obj.get("time")
        if isinstance(raw_ts, str):
            try:
                ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                ts = None
        elif isinstance(raw_ts, (int, float)):
            try:
                ts = datetime.fromtimestamp(raw_ts / 1e9, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                ts = None
        priority = str(obj.get("priority", "")).lower()
        severity = _PRIORITY.get(priority, Severity.WARNING)
        extra: dict[str, object] = {
            "rule": obj.get("rule"),
            "priority": obj.get("priority"),
            "source": obj.get("source"),
        }
        fields = obj.get("output_fields")
        if isinstance(fields, dict):
            for k in ("proc.name", "user.name", "container.id", "k8s.pod.name"):
                if k in fields:
                    extra[k] = fields[k]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=str(obj.get("hostname") or "falco"),
            message=str(obj.get("output", "")),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
