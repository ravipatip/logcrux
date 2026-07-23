from __future__ import annotations

import json
import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# MongoDB 4.4+ emits structured JSON log lines, one object per line:
#   {"t":{"$date":"2024-06-20T10:23:45.123+00:00"},"s":"I","c":"NETWORK",
#    "id":22943,"ctx":"listener","msg":"Connection accepted","attr":{...}}
# Severity field "s": F=fatal, E=error, W=warning, I=info, D/D1-D5=debug.
_SEVERITY_MAP: dict[str, Severity] = {
    "F": Severity.CRITICAL,
    "E": Severity.ERROR,
    "W": Severity.WARNING,
    "I": Severity.INFO,
    "D": Severity.DEBUG,
}

# Legacy MongoDB 3.x text format:
#   2019-06-20T10:23:45.123+0000 I NETWORK  [listener] connection accepted ...
_LEGACY_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4}) "
    r"(?P<sev>[FEWID])\d? "
    r"(?P<component>[A-Z]+)\s+"
    r"\[(?P<ctx>[^\]]+)\] "
    r"(?P<message>.*)"
)


def _legacy_severity(letter: str) -> Severity:
    return _SEVERITY_MAP.get(letter, Severity.INFO)


class MongoDBParser(LogParser):
    FORMAT_NAME = "mongodb"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "mongo" in path.name.lower():
            return True
        for line in sample_lines[:10]:
            stripped = line.strip()
            if stripped.startswith('{"t":{"$date"') and '"s":' in stripped:
                return True
            if _LEGACY_PATTERN.match(stripped):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        line = line.strip()
        if not line:
            return None
        if line.startswith("{"):
            return self._parse_json(line, line_number)
        m = _LEGACY_PATTERN.match(line)
        if m:
            return self._parse_legacy(m, line, line_number)
        return None

    def _parse_json(self, line: str, line_number: int) -> ParsedEvent | None:
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(obj, dict) or "s" not in obj or "msg" not in obj:
            return None
        ts_raw = (obj.get("t") or {}).get("$date") if isinstance(obj.get("t"), dict) else None
        ts = None
        if ts_raw:
            try:
                ts = dateparser.parse(ts_raw)
            except (ValueError, TypeError, OverflowError):
                ts = None
        message = str(obj.get("msg", ""))
        attr = obj.get("attr")
        if isinstance(attr, dict) and attr:
            # Fold the structured attributes into the message so keyword-based
            # anomaly detection (OOM, connection errors, ...) can see them.
            message = f"{message} {json.dumps(attr, separators=(',', ':'))}"
        extra: dict[str, object] = {"component": obj.get("c"), "ctx": obj.get("ctx")}
        if "id" in obj:
            extra["log_id"] = obj["id"]
        return ParsedEvent(
            timestamp=ts,
            severity=_SEVERITY_MAP.get(str(obj.get("s")), Severity.INFO),
            source="mongodb",
            message=message.strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )

    def _parse_legacy(self, m: re.Match[str], line: str, line_number: int) -> ParsedEvent:
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_legacy_severity(m["sev"]),
            source="mongodb",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"component": m["component"], "ctx": m["ctx"]},
        )
