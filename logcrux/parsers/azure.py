from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Azure Monitor / Activity Log JSON export — one record per line keyed by
# "operationName" + "category" with an Azure "level" word:
#   {"time":"2026-06-20T10:15:01.123Z","resourceId":"/SUBSCRIPTIONS/...",
#    "operationName":"Microsoft.Compute/virtualMachines/write","category":
#    "Administrative","level":"Information","resultType":"Success"}
_LEVEL_MAP: dict[str, Severity] = {
    "verbose": Severity.DEBUG,
    "informational": Severity.INFO,
    "information": Severity.INFO,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "critical": Severity.CRITICAL,
}


def _is_azure(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "operationName" in obj
        and "category" in obj
        and ("resourceId" in obj or "time" in obj)
    )


class AzureParser(LogParser):
    FORMAT_NAME = "azure"

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
            if _is_azure(obj):
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
        if not _is_azure(obj):
            return None
        ts = None
        t_raw = obj.get("time")
        if isinstance(t_raw, str):
            try:
                ts = dateparser.parse(t_raw)
            except (ValueError, TypeError, OverflowError):
                ts = None
        level = str(obj.get("level", "Informational")).lower()
        severity = _LEVEL_MAP.get(level, Severity.INFO)
        result = str(obj.get("resultType", ""))
        if result.lower() in ("failure", "failed") and severity == Severity.INFO:
            severity = Severity.WARNING
        operation = str(obj.get("operationName", ""))
        message = operation
        if result:
            message = f"{operation} ({result})"
        extra: dict[str, object] = {
            "level": level,
            "category": obj.get("category"),
        }
        if "resourceId" in obj:
            extra["resource_id"] = obj["resourceId"]
        if result:
            extra["result"] = result
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="azure",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
