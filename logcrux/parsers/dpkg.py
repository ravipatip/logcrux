from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Debian/Ubuntu dpkg.log:
#   2026-06-20 10:15:01 startup archives unpack
#   2026-06-20 10:15:01 install nginx:amd64 <none> 1.24.0-1
#   2026-06-20 10:15:02 status installed nginx:amd64 1.24.0-1
#   2026-06-20 10:15:02 status half-configured nginx:amd64 1.24.0-1
_ACTIONS = (
    "startup", "status", "install", "upgrade", "remove", "purge",
    "configure", "trigproc", "conffile", "disappear",
)
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<action>" + "|".join(_ACTIONS) + r")\b(?P<rest>.*)$"
)


class DpkgParser(LogParser):
    FORMAT_NAME = "dpkg"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "dpkg" in path.name.lower():
            return True
        matched = sum(1 for ln in sample_lines[:20] if _PATTERN.match(ln))
        nonblank = sum(1 for ln in sample_lines[:20] if ln.strip())
        return nonblank > 0 and matched * 2 >= nonblank

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        rest = m["rest"].strip()
        # half-installed / half-configured states indicate an interrupted op.
        severity = Severity.WARNING if "half-" in rest else Severity.INFO
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="dpkg",
            message=f'{m["action"]} {rest}'.strip(),
            raw=line,
            line_number=line_number,
            extra={"action": m["action"]},
        )
