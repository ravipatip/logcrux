from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# Time-sync daemons (chronyd / ntpd) logging through syslog.
#   May 19 10:15:01 host chronyd[1234]: Selected source 192.168.1.1
#   May 19 10:15:02 host chronyd[1234]: System clock wrong by 1.234 seconds, adjustment started
#   May 19 10:15:03 host ntpd[1234]: no servers reachable
#   May 19 10:15:04 host chronyd[1234]: Source 10.0.0.5 unreachable
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>chronyd|ntpd|ntpdate|systemd-timesyncd)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

_SOURCE_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_CURRENT_YEAR = datetime.now().year

_ERROR_KEYWORDS = frozenset(
    ["no servers reachable", "cannot", "could not", "failed", "fatal",
     "unable to", "no suitable source", "time may be in error",
     "no reply", "panic", "exiting"]
)
_WARN_KEYWORDS = frozenset(
    ["unreachable", "wrong by", "clock wrong", "step", "stratum change",
     "fell back", "not synchronised", "not synchronized", "leap second",
     "frequency", "slew", "rejected", "ignoring"]
)


def _chrony_severity(message: str) -> Severity:
    low = message.lower()
    if any(k in low for k in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(k in low for k in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class ChronyParser(LogParser):
    FORMAT_NAME = "chrony"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            name = path.name.lower()
            if "chrony" in name or "ntp" in name:
                return True
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(
                f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
            )
        except Exception:
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"program": m["prog"]}
        if m["pid"]:
            extra["pid"] = m["pid"]
        src = _SOURCE_IP_RE.search(message)
        if src:
            extra["source_ip"] = src.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_chrony_severity(message),
            source=m["prog"],
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
