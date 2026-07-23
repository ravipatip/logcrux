from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# smartd (S.M.A.R.T. disk monitoring) logs through syslog. Program tag smartd:
#   Jun 20 10:23:45 host smartd[1234]: Device: /dev/sda [SAT], 5 Currently \
#       unreadable (pending) sectors
#   Jun 20 10:23:45 host smartd[1234]: Device: /dev/sdb [SAT], FAILED SMART \
#       self-check. BACK UP DATA NOW!
#   Jun 20 10:23:45 host smartd[1234]: Device: /dev/sda [SAT], SMART Usage \
#       Attribute: 194 Temperature_Celsius changed from 35 to 41
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>smartd)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

_DEVICE_RE = re.compile(r"Device:\s+(?P<dev>/dev/\S+)")
_CURRENT_YEAR = datetime.now().year

# Impending-failure signals — high precision for "my disk is dying".
_ERROR_KEYWORDS = frozenset([
    "failed smart", "failed self", "self-test log error", "back up data now",
    "read failure", "ata error", "in the past", "failing_now",
    "unrecoverable", "device disappeared", "cannot", "failed to read",
    "previously recorded", "fatal",
])
_WARN_KEYWORDS = frozenset([
    "unreadable", "pending", "offline uncorrectable", "reallocated",
    "changed from", "increased", "temperature", "sector", "prefailure",
    "below threshold", "warning",
])


def _smartd_severity(message: str) -> Severity:
    low = message.lower()
    if any(kw in low for kw in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(kw in low for kw in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class SmartdParser(LogParser):
    FORMAT_NAME = "smartd"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "smartd" in path.name.lower():
            return True
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}")
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"program": "smartd"}
        if m["pid"]:
            extra["pid"] = m["pid"]
        dev = _DEVICE_RE.search(message)
        if dev:
            extra["device"] = dev["dev"]
        return ParsedEvent(
            timestamp=ts,
            severity=_smartd_severity(message),
            source="smartd",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
