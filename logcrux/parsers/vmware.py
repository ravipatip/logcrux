from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# VMware ESXi vmkernel.log. Layout is "ts cpuN:world)[LEVEL:] subsystem: msg":
#   2026-06-28T10:15:01.123Z cpu0:2097152)ScsiDeviceIO: 1234: Cmd 0x28 success
#   2026-06-28T10:15:02.234Z cpu1:2097153)WARNING: NMP: nmp_PathDetermineFailure
#   2026-06-28T10:15:03.345Z cpu2:2097154)ALERT: Bootbank cannot be found
# The "cpuN:<world>)" prefix after an ISO-Z timestamp is the ESXi signature.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z) "
    r"cpu(?P<cpu>\d+):(?P<world>\d+)\)"
    r"(?:(?P<level>WARNING|ALERT|ERROR):\s*)?"
    r"(?P<message>.*)$"
)
_LEVEL_MAP = {
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "ALERT": Severity.CRITICAL,
}


class VMwareParser(LogParser):
    FORMAT_NAME = "vmware"

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
        extra: dict[str, object] = {"cpu": m["cpu"], "world": m["world"]}
        if m["level"]:
            extra["level"] = m["level"]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO) if m["level"] else Severity.INFO,
            source="vmware",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
