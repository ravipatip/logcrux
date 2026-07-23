from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Microsoft SQL Server ERRORLOG. Two-digit fractional seconds and a padded
# source column (spidNN / Server / Logon / Backup) make it distinct from other
# "YYYY-MM-DD HH:MM:SS" logs:
#   2026-06-20 10:15:01.45 spid51      Starting up database 'master'.
#   2026-06-20 10:15:02.00 Logon       Login failed for user 'sa'. Reason: ...
#   2026-06-20 10:15:03.11 spid55      Error: 18456, Severity: 14, State: 1.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{2}) "
    r"(?P<source>spid\d+\w*|Server|Logon|Backup|Library|Service Broker)\s{2,}"
    r"(?P<message>.*)$"
)
_SEVERITY_RE = re.compile(r"Severity:\s*(\d+)")


def _mssql_severity(message: str) -> Severity:
    sm = _SEVERITY_RE.search(message)
    if sm:
        sev = int(sm.group(1))
        if sev >= 17:
            return Severity.CRITICAL
        if sev >= 11:
            return Severity.ERROR
    low = message.lower()
    if low.startswith("error:") or "fatal" in low or "cannot" in low:
        return Severity.ERROR
    if "login failed" in low or "failed" in low or "warning" in low:
        return Severity.WARNING
    return Severity.INFO


class MSSQLParser(LogParser):
    FORMAT_NAME = "mssql"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _PATTERN.match(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        return ParsedEvent(
            timestamp=ts,
            severity=_mssql_severity(message),
            source="mssql",
            message=message,
            raw=line,
            line_number=line_number,
            extra={"spid": m["source"]},
        )
