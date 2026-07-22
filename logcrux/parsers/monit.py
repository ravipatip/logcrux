from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Monit process/host monitor log. Each line is "[TZ Mon DD HH:MM:SS] level  :
# message":
#   [UTC Jun 28 10:15:01] info     : Starting Monit 5.33
#   [UTC Jun 28 10:15:02] error    : 'rootfs' space usage 95.0% matches resource
#   [UTC Jun 28 10:15:03] info     : 'nginx' process is running with pid 1234
# The "[TZ Mon DD HH:MM:SS] level : " shape is the distinctive signature.
_PATTERN = re.compile(
    r"^\[(?P<tz>\w{2,4}) (?P<month>\w{3})\s+(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2})\] "
    r"(?P<level>\w+)\s*: (?P<message>.*)$"
)
_LEVEL_MAP = {
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "critical": Severity.CRITICAL,
}
_CURRENT_YEAR = datetime.now().year


class MonitParser(LogParser):
    FORMAT_NAME = "monit"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(
                f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
            )
        except Exception:
            ts = None
        level = m["level"].lower()
        message = m["message"].strip()
        severity = _LEVEL_MAP.get(level, Severity.INFO)
        # Monit logs resource-limit alerts at "error"; surface the watched object.
        extra: dict[str, object] = {"level": level}
        obj = re.match(r"'([^']+)'", message)
        if obj:
            extra["service"] = obj.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="monit",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
