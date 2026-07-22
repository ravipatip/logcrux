from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Elastic Beats (Filebeat / Metricbeat / Auditbeat) internal log — ECS JSON, one
# object per line. Identified by the dotted "log.level" + "@timestamp" keys
# (distinct from Winston's "level"/"timestamp"):
#   {"log.level":"info","@timestamp":"2026-06-20T10:15:01.123Z","log.logger":
#    "publisher","message":"start pipeline","service.name":"filebeat","ecs.version":"1.6.0"}
#   {"log.level":"error","@timestamp":"...","message":"Failed to connect to ES",
#    "service.name":"filebeat","ecs.version":"1.6.0"}


def _is_filebeat(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "log.level" in obj
        and "@timestamp" in obj
        and "message" in obj
    )


class FilebeatParser(LogParser):
    FORMAT_NAME = "filebeat"

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
            if _is_filebeat(obj):
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
        if not _is_filebeat(obj):
            return None
        ts = None
        try:
            ts = dateparser.parse(str(obj["@timestamp"]))
        except (ValueError, TypeError, OverflowError):
            ts = None
        level = str(obj.get("log.level", "info"))
        extra: dict[str, object] = {
            "level": level,
            "service": obj.get("service.name"),
            "logger": obj.get("log.logger"),
        }
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source=str(obj.get("service.name") or "filebeat"),
            message=str(obj.get("message", "")),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
