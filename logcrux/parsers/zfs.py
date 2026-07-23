from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# ZFS Event Daemon (zed) syslog output — the operational signal for ZFS pools.
# Each line is syslog-tagged "zed[pid]:" with key=value ZFS event fields:
#   Jun 28 10:15:01 host zed[1234]: eid=5 class=checksum pool='tank' vdev=...
#   Jun 28 10:15:02 host zed[1234]: eid=6 class=statechange pool='tank'
#   Jun 28 10:15:03 host zed[1234]: eid=7 class=data pool='tank'
# The "zed[pid]: ... class=<event>" shape is the distinctive signature.
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) zed\[(?P<pid>\d+)\]: (?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year
# Hard-fault classes -> ERROR; transient/degraded states -> WARNING.
_ERROR_CLASSES = ("checksum", "io", "data", "deadman", "delay", "failure",
                  "removed", "fault")
_WARN_CLASSES = ("statechange", "scrub", "resilver", "degraded", "trim",
                 "probe_failure", "config")


class ZfsParser(LogParser):
    FORMAT_NAME = "zfs"

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
        cls_m = re.search(r"class=(\S+)", message)
        severity = Severity.INFO
        if cls_m:
            event_class = cls_m.group(1).split(".")[-1]
            extra["event_class"] = event_class
            if any(c in event_class for c in _ERROR_CLASSES):
                severity = Severity.ERROR
            elif any(c in event_class for c in _WARN_CLASSES):
                severity = Severity.WARNING
        pool_m = re.search(r"pool='([^']+)'", message)
        if pool_m:
            extra["pool"] = pool_m.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="zfs",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
