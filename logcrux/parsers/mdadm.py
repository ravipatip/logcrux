from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# Linux software-RAID monitor (mdadm --monitor) syslog output. Tagged "mdadm":
#   Jun 28 10:15:01 host mdadm[1234]: DegradedArray event detected on md device /dev/md0
#   Jun 28 10:15:02 host mdadm[1234]: Fail event detected on md device /dev/md0, component /dev/sdb1
#   Jun 28 10:15:03 host mdadm[1234]: RebuildStarted event detected on md device /dev/md0
#   Jun 28 10:15:04 host mdadm[1234]: SpareActive event detected on md device /dev/md0
# The "<Event> event detected on md device" shape is the distinctive signature.
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) mdadm\[(?P<pid>\d+)\]: (?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year
_ERROR_EVENTS = ("Fail", "DegradedArray", "DeviceDisappeared", "FailSpare")
_WARN_EVENTS = ("Rebuild", "SpareActive", "TestMessage", "MoveSpare")


class MdadmParser(LogParser):
    FORMAT_NAME = "mdadm"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}")
        except Exception:
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"pid": m["pid"]}
        ev_m = re.match(r"(\w+) event detected on md device ([^\s,]+)", message)
        severity = Severity.INFO
        if ev_m:
            event = ev_m.group(1)
            extra["event"] = event
            extra["device"] = ev_m.group(2)
            if any(event.startswith(e) for e in _ERROR_EVENTS):
                severity = Severity.ERROR
            elif any(event.startswith(e) for e in _WARN_EVENTS):
                severity = Severity.WARNING
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="mdadm",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
