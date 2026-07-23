from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# GitLab structured logs (production_json.log, api_json.log, application_json.log)
# emit one JSON object per line:
#   {"severity":"INFO","time":"2026-06-23T10:23:45.123Z","correlation_id":"abc",
#    "method":"GET","path":"/api/v4/projects","status":200,"duration_s":0.08}
#   {"severity":"ERROR","time":"2026-06-23T10:23:45.123Z","correlation_id":"def",
#    "exception.class":"ActiveRecord::RecordNotFound","message":"not found"}
# Distinguished from GCP by ``time`` (not ``timestamp``) plus a GitLab-specific
# key (correlation_id / method+path / exception.class / meta.caller_id).
_GITLAB_MARKERS = (
    "correlation_id",
    "meta.caller_id",
    "exception.class",
    "controller",
)


def _is_gitlab(obj: object) -> bool:
    if not isinstance(obj, dict):
        return False
    if "severity" not in obj or "time" not in obj:
        return False
    if any(k in obj for k in _GITLAB_MARKERS):
        return True
    return "method" in obj and "path" in obj


class GitLabParser(LogParser):
    FORMAT_NAME = "gitlab"

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
            if _is_gitlab(obj):
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
        if not _is_gitlab(obj):
            return None
        ts: datetime | None
        try:
            ts = dateparser.parse(str(obj["time"]))
        except (ValueError, TypeError, OverflowError):
            ts = None
        severity = level_to_severity(str(obj.get("severity", "info")))
        if "method" in obj and "path" in obj:
            message = f"{obj['method']} {obj['path']}"
            if "status" in obj:
                message += f" -> {obj['status']}"
                try:
                    if int(obj["status"]) >= 500:
                        severity = Severity.ERROR
                    elif int(obj["status"]) >= 400 and severity is Severity.INFO:
                        severity = Severity.WARNING
                except (ValueError, TypeError):
                    pass
        else:
            message = str(
                obj.get("message")
                or obj.get("exception.message")
                or obj.get("exception.class")
                or ""
            )
        extra: dict[str, object] = {"severity": str(obj.get("severity"))}
        for key in ("correlation_id", "controller", "exception.class", "status"):
            if key in obj:
                extra[key] = obj[key]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="gitlab",
            message=message.strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
