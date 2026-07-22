from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# libvirt daemon / per-VM logs (libvirtd.log, qemu/<vm>.log). Layout is
# "ts+offset: pid: level : func:line : message":
#   2026-06-28 10:15:01.123+0000: 1234: info : libvirt version: 9.0.0
#   2026-06-28 10:15:02.234+0000: 1234: warning : qemuDomainObjTaint:1234 : Domain tainted
#   2026-06-28 10:15:03.345+0000: 1234: error : qemuMonitorIO:599 : internal error: closed
# The "ts+0000: pid: level : " shape is the distinctive libvirt signature.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[+-]\d{4}): "
    r"(?P<pid>\d+): "
    r"(?P<level>debug|info|warning|error) : "
    r"(?:(?P<loc>\S+:\d+) : )?"
    r"(?P<message>.*)$"
)


class LibvirtParser(LogParser):
    FORMAT_NAME = "libvirt"

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
        extra: dict[str, object] = {"level": m["level"], "pid": m["pid"]}
        if m["loc"]:
            extra["location"] = m["loc"]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="libvirt",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
