from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# Keepalived (VRRP / LVS health-checking) logs through syslog. Program tags:
#   Keepalived, Keepalived_vrrp, Keepalived_healthcheckers
#   Jun 20 10:23:45 host Keepalived_vrrp[1234]: VRRP_Instance(VI_1) Entering MASTER STATE
#   Jun 20 10:23:45 host Keepalived_vrrp[1234]: VRRP_Instance(VI_1) Entering FAULT STATE
#   Jun 20 10:23:45 host Keepalived_healthcheckers[1235]: Check failed for [10.0.0.5]:80
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>Keepalived(?:_vrrp|_healthcheckers)?)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

_INSTANCE_RE = re.compile(r"VRRP_Instance\((?P<name>[^)]+)\)")
_CURRENT_YEAR = datetime.now().year

# State transitions and check failures are what an HA operator watches for.
_ERROR_KEYWORDS = frozenset([
    "entering fault state", "now in fault", "check failed", "removing service",
    "unable to", "cannot", "failed", "no such", "lost quorum",
    "error", "invalid", "timeout",
])
_WARN_KEYWORDS = frozenset([
    "entering master state", "entering backup state", "received advert",
    "received lower prio", "transition", "ignoring", "received higher prio",
    "going down", "re-entering",
])


def _keepalived_severity(message: str) -> Severity:
    low = message.lower()
    if any(kw in low for kw in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(kw in low for kw in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class KeepalivedParser(LogParser):
    FORMAT_NAME = "keepalived"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "keepalived" in path.name.lower():
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
        extra: dict[str, object] = {"program": m["prog"]}
        if m["pid"]:
            extra["pid"] = m["pid"]
        inst = _INSTANCE_RE.search(message)
        if inst:
            extra["vrrp_instance"] = inst["name"]
        return ParsedEvent(
            timestamp=ts,
            severity=_keepalived_severity(message),
            source=m["prog"],
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
