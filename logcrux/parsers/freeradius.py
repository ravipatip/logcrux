from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# FreeRADIUS radiusd log. ctime-style timestamp + a category word:
#   Mon Jun 20 10:15:01 2026 : Info: Loaded virtual server default
#   Mon Jun 20 10:15:02 2026 : Auth: Login OK: [bob] (from client ap1 port 0)
#   Mon Jun 20 10:15:03 2026 : Auth: Login incorrect (mschap): [alice] (from ...)
#   Mon Jun 20 10:15:04 2026 : Error: Failed binding to auth address
_PATTERN = re.compile(
    r"^(?P<ts>\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) : "
    r"(?P<level>Info|Auth|Error|Warning|Debug|Proxy|Acct|Info\(\d+\)): "
    r"(?P<message>.*)$"
)
_FAIL_MARKERS = ("login incorrect", "rejected", "access-reject", "invalid user", "failed")


class FreeRadiusParser(LogParser):
    FORMAT_NAME = "freeradius"

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
        level = m["level"]
        message = m["message"].strip()
        low = message.lower()
        if level == "Error":
            severity = Severity.ERROR
        elif level == "Warning":
            severity = Severity.WARNING
        elif level == "Auth" and any(k in low for k in _FAIL_MARKERS):
            # Failed authentication — the brute-force signal feeds on these.
            severity = Severity.WARNING
        elif level == "Debug":
            severity = Severity.DEBUG
        else:
            severity = Severity.INFO
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="freeradius",
            message=message,
            raw=line,
            line_number=line_number,
            extra={"category": level.lower()},
        )
