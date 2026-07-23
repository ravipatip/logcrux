from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# APT history log (/var/log/apt/history.log) — blocks of "Key: value" lines:
#   Start-Date: 2026-06-20  10:15:01
#   Commandline: apt install nginx
#   Requested-By: alice (1000)
#   Install: nginx:amd64 (1.24.0-1), libpcre3:amd64 (2:8.39)
#   Error: Sub-process /usr/bin/dpkg returned an error code (1)
#   End-Date: 2026-06-20  10:15:08
_KEYS = (
    "Start-Date", "End-Date", "Commandline", "Requested-By",
    "Install", "Upgrade", "Remove", "Purge", "Downgrade", "Reinstall", "Error",
)
_PATTERN = re.compile(r"^(?P<key>" + "|".join(_KEYS) + r"): (?P<value>.*)$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}")


class AptHistoryParser(LogParser):
    FORMAT_NAME = "apthistory"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "history.log" in str(path).lower():
            # confirm it's apt history and not some other "history.log"
            if any(ln.startswith("Start-Date:") or ln.startswith("Commandline:")
                   for ln in sample_lines[:20]):
                return True
        starts = sum(1 for ln in sample_lines[:20] if ln.startswith("Start-Date:"))
        cmds = sum(1 for ln in sample_lines[:20] if ln.startswith("Commandline:"))
        return starts > 0 and cmds > 0

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        key, value = m["key"], m["value"].strip()
        ts = None
        if key in ("Start-Date", "End-Date") and _DATE_RE.match(value):
            try:
                ts = dateparser.parse(value)
            except (ValueError, TypeError, OverflowError):
                ts = None
        severity = Severity.ERROR if key == "Error" else Severity.INFO
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="apt",
            message=f"{key}: {value}",
            raw=line,
            line_number=line_number,
            extra={"field": key},
        )
