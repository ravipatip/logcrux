from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# RHEL/CentOS yum.log (and dnf.log legacy form):
#   Jun 20 10:15:01 Installed: nginx-1.24.0-1.el9.x86_64
#   Jun 20 10:15:02 Updated: openssl-3.0.7-1.el9.x86_64
#   Jun 20 10:15:03 Erased: oldpkg-1.0.x86_64
_ACTIONS = (
    "Installed", "Updated", "Erased", "Obsoleted", "Reinstalled",
    "Downgraded", "Removed",
)
_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<action>" + "|".join(_ACTIONS) + r"): (?P<pkg>.+)$"
)
_CURRENT_YEAR = datetime.now().year


class YumParser(LogParser):
    FORMAT_NAME = "yum"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and re.search(r"(yum|dnf)\.log", path.name.lower()):
            return True
        matched = sum(1 for ln in sample_lines[:20] if _PATTERN.match(ln))
        nonblank = sum(1 for ln in sample_lines[:20] if ln.strip())
        return nonblank > 0 and matched * 2 >= nonblank

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f'{m["month"]} {m["day"]} {_CURRENT_YEAR} {m["time"]}')
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=Severity.INFO,
            source="yum",
            message=f'{m["action"]}: {m["pkg"].strip()}',
            raw=line,
            line_number=line_number,
            extra={"action": m["action"], "package": m["pkg"].strip()},
        )
