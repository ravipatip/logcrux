from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Oracle Database alert log (12c+ format). Records are multi-line: a bare ISO
# timestamp line precedes one or more message lines, and errors surface as
# ORA-/TNS- codes:
#   2026-06-20T10:15:01.123456+00:00
#   Starting ORACLE instance (normal)
#   2026-06-20T10:15:02.000000+00:00
#   ORA-00600: internal error code, arguments: [4194], [], []
# The parser carries the most recent timestamp header onto the lines beneath it.
_TS_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+\-Z]")
_ORA_RE = re.compile(r"\b(ORA|TNS)-(\d{4,5})\b")
# ORA codes that indicate a crash / corruption / internal error.
_CRITICAL_ORA = frozenset({"00600", "07445", "00603", "01578", "00204", "27300"})
_STARTUP_MARKERS = ("Starting ORACLE instance", "Instance shutdown", "ALTER DATABASE")


class OracleParser(LogParser):
    FORMAT_NAME = "oracle"

    def __init__(self) -> None:
        self._last_ts: datetime | None = None

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "alert" in path.name.lower():
            for ln in sample_lines[:30]:
                if _TS_ONLY_RE.match(ln) or _ORA_RE.search(ln):
                    return True
        has_ora = any(_ORA_RE.search(ln) for ln in sample_lines[:40])
        has_marker = any(mk in ln for ln in sample_lines[:40] for mk in _STARTUP_MARKERS)
        return has_ora and has_marker

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if _TS_ONLY_RE.match(line) and len(line.strip()) <= 40:
            try:
                self._last_ts = dateparser.parse(line.strip())
            except (ValueError, TypeError, OverflowError):
                self._last_ts = None
            self.meta_lines += 1
            return None
        if not line.strip():
            return None
        m = _ORA_RE.search(line)
        severity = Severity.INFO
        extra: dict[str, object] = {}
        if m:
            code = m.group(2)
            extra["error_code"] = f"{m.group(1)}-{code}"
            severity = Severity.CRITICAL if code in _CRITICAL_ORA else Severity.ERROR
        elif "Errors in file" in line:
            severity = Severity.WARNING
        return ParsedEvent(
            timestamp=self._last_ts,
            severity=severity,
            source="oracle",
            message=line.strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
