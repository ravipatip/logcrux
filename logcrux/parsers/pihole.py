from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Pi-hole FTL engine log (FTL.log). Layout is "[ts pidT] message", where the pid
# carries a thread suffix letter (M=main, F=fork, etc.):
#   [2026-06-28 10:15:01.123 1234M] Starting FTL
#   [2026-06-28 10:15:02.234 1234M] WARNING: Unable to read /etc/pihole/...
#   [2026-06-28 10:15:03.345 1235F] ERROR: Database query failed
# The "[ts <pid><letter>]" bracket prefix is the distinctive FTL signature.
_PATTERN = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) "
    r"(?P<pid>\d+[A-Z])\] "
    r"(?P<message>.*)$"
)


class PiholeParser(LogParser):
    FORMAT_NAME = "pihole"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:25])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        severity = Severity.INFO
        if message.startswith("ERROR") or message.startswith("FATAL"):
            severity = Severity.ERROR
        elif message.startswith("WARNING"):
            severity = Severity.WARNING
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="pihole",
            message=message,
            raw=line,
            line_number=line_number,
            extra={"pid": m["pid"]},
        )
