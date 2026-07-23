from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# pfSense / OPNsense packet-filter logs, written through syslog by "filterlog".
# After the tag comes a CSV record (layout differs slightly between IPv4/IPv6):
#   Jun 20 10:15:01 fw filterlog[123]: 100,,,1000000103,igb0,match,block,in,4,
#       0x0,,64,12345,0,DF,6,tcp,60,1.2.3.4,5.6.7.8,55000,443,...
# Stable leading fields: rulenum, subrule, anchor, tracker, interface, reason,
# action, direction, ip_version. block/reject actions are the interesting ones.
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) filterlog(?:\[(?P<pid>\d+)\])?: (?P<csv>.*)"
)
_CURRENT_YEAR = datetime.now().year


class PfSenseParser(LogParser):
    FORMAT_NAME = "pfsense"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}")
        except (ValueError, TypeError, OverflowError):
            ts = None
        fields = m["csv"].split(",")
        # Positional leading fields (present for both IPv4 and IPv6 records).
        interface = fields[4] if len(fields) > 4 else "?"
        action = fields[6] if len(fields) > 6 else ""
        direction = fields[7] if len(fields) > 7 else ""
        ip_version = fields[8] if len(fields) > 8 else ""
        # proto / addresses sit at different offsets for v4 vs v6.
        proto = src = dst = ""
        if ip_version == "4" and len(fields) >= 21:
            proto, src, dst = fields[16], fields[18], fields[19]
        elif ip_version == "6" and len(fields) >= 19:
            proto, src, dst = fields[12], fields[15], fields[16]
        severity = Severity.WARNING if action in {"block", "reject"} else Severity.INFO
        message = f"{action} {direction} {proto} {src} -> {dst} on {interface}".strip()
        extra: dict[str, object] = {
            "action": action,
            "interface": interface,
            "direction": direction,
        }
        if src:
            extra["src"] = src
        if dst:
            extra["dst"] = dst
        if m["pid"]:
            extra["pid"] = m["pid"]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="filterlog",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
