from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# FRRouting / Quagga routing-daemon syslog output (bgpd, ospfd, zebra, ...).
# Tagged with the per-protocol daemon name:
#   Jun 28 10:15:01 host bgpd[1234]: [EC 33554503] bgp_session: neighbor 10.0.0.2 Up
#   Jun 28 10:15:02 host ospfd[1235]: interface eth0 down
#   Jun 28 10:15:03 host zebra[1236]: [EC 4043309089] netlink: error: No such device
# The per-protocol routing-daemon tag is the distinctive FRR signature.
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<daemon>bgpd|ospfd|ospf6d|ripd|ripngd|isisd|zebra|staticd|bfdd|pimd|"
    r"pim6d|ldpd|nhrpd|babeld|fabricd|vrrpd|pbrd|pathd|sharpd)"
    r"\[(?P<pid>\d+)\]: (?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year
_ERROR_KW = ("error", "failed", "cannot", "no such", "down", "lost", "reset",
             "denied", "unreachable", "invalid", "drop")
_WARN_KW = ("warn", "retry", "flap", "timeout", "withdraw", "notification",
            "shutdown", "stale", "holdtime")


class FrrParser(LogParser):
    FORMAT_NAME = "frr"

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
        low = message.lower()
        severity = Severity.INFO
        if any(k in low for k in _WARN_KW):
            severity = Severity.WARNING
        if any(k in low for k in _ERROR_KW):
            severity = Severity.ERROR
        extra: dict[str, object] = {"daemon": m["daemon"], "pid": m["pid"]}
        ec_m = re.match(r"\[EC (\d+)\]", message)
        if ec_m:
            extra["error_code"] = ec_m.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="frr",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
