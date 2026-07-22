from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser


# osquery (osqueryd) results log — JSON, one scheduled-query diff per line:
#   {"name":"pack_incident_response_process_events","hostIdentifier":"node1",
#    "calendarTime":"Sat Jun 28 10:15:01 2026 UTC","unixTime":1782000901,
#    "epoch":0,"counter":1,"action":"added","columns":{"pid":"1234",...}}
# Distinguished by hostIdentifier + calendarTime + columns + action.
def _is_osquery(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "hostIdentifier" in obj
        and ("calendarTime" in obj or "unixTime" in obj)
        and ("columns" in obj or "snapshot" in obj)
    )


class OsqueryParser(LogParser):
    FORMAT_NAME = "osquery"

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
            if _is_osquery(obj):
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
        if not _is_osquery(obj):
            return None
        ts = None
        unix = obj.get("unixTime")
        if isinstance(unix, (int, float)):
            try:
                ts = datetime.fromtimestamp(unix, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                ts = None
        if ts is None and isinstance(obj.get("calendarTime"), str):
            try:
                ts = dateparser.parse(obj["calendarTime"])
            except (ValueError, TypeError, OverflowError):
                ts = None
        action = str(obj.get("action", ""))
        # A removed/added FIM or process-event row is noteworthy but not an
        # error; surface the query name + action as the message.
        name = str(obj.get("name", "osquery"))
        severity = Severity.WARNING if action == "removed" else Severity.INFO
        columns = obj.get("columns")
        detail = ""
        if isinstance(columns, dict):
            detail = " ".join(f"{k}={v}" for k, v in list(columns.items())[:6])
        message = f"{name} [{action}] {detail}".strip()
        extra: dict[str, object] = {
            "name": name,
            "action": action or None,
            "host": obj.get("hostIdentifier"),
        }
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=str(obj.get("hostIdentifier") or "osquery"),
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
