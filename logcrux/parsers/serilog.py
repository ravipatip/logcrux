from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# Serilog / .NET CLEF (Compact Log Event Format) emits one JSON object per line
# whose fields are prefixed with "@":
#   {"@t":"2026-06-20T10:15:01.123Z","@m":"User logged in","@l":"Warning","@i":"a1b2"}
# "@t" (timestamp) + "@m"/"@mt" (message / template) are the signature keys.
# "@l" is omitted for Information (the default level).


def _is_clef(obj: object) -> bool:
    return isinstance(obj, dict) and "@t" in obj and ("@m" in obj or "@mt" in obj)


class SerilogParser(LogParser):
    FORMAT_NAME = "serilog"

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
            if _is_clef(obj):
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
        if not _is_clef(obj):
            return None
        ts = None
        t_raw = obj.get("@t")
        if isinstance(t_raw, str):
            try:
                ts = dateparser.parse(t_raw)
            except (ValueError, TypeError, OverflowError):
                ts = None
        # CLEF omits "@l" for Information; an "@x" exception escalates to error.
        level = str(obj.get("@l", "information"))
        severity = level_to_severity(level)
        if "@x" in obj and severity.value in ("info", "debug"):
            severity = Severity.ERROR
        message = str(obj.get("@m") or obj.get("@mt") or "")
        extra: dict[str, object] = {"level": level.lower()}
        if "@x" in obj:
            extra["exception"] = str(obj["@x"]).splitlines()[0] if obj["@x"] else ""
        if "@i" in obj:
            extra["event_id"] = obj["@i"]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="serilog",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
