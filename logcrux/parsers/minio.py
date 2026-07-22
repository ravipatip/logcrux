from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# MinIO (object storage) JSON logger — one object per line carrying the MinIO-
# specific "errKind" field alongside level/time/message:
#   {"level":"ERROR","errKind":"ALL","time":"2026-06-20T10:15:01.123Z",
#    "api":{"name":"PutObject"},"error":{"message":"disk full","source":["..."]}}


def _is_minio(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "errKind" in obj
        and "level" in obj
        and "time" in obj
    )


class MinioParser(LogParser):
    FORMAT_NAME = "minio"

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
            if _is_minio(obj):
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
        if not _is_minio(obj):
            return None
        ts = None
        t_raw = obj.get("time")
        if isinstance(t_raw, str):
            try:
                ts = dateparser.parse(t_raw)
            except (ValueError, TypeError, OverflowError):
                ts = None
        level = str(obj.get("level", "info"))
        message = str(obj.get("message", ""))
        extra: dict[str, object] = {"level": level.lower(), "errKind": obj.get("errKind")}
        err = obj.get("error")
        if isinstance(err, dict):
            msg = str(err.get("message", ""))
            if msg:
                message = msg if not message else f"{message}: {msg}"
        api = obj.get("api")
        if isinstance(api, dict) and "name" in api:
            extra["api"] = api["name"]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source="minio",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
