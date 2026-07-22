from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# PowerDNS (authoritative / recursor) logging through syslog:
#   Jun 20 10:15:01 host pdns_server[1234]: Creating backend connection
#   Jun 20 10:15:02 host pdns_recursor[1234]: Inserting forward zone
#   Jun 20 10:15:03 host pdns_server[1234]: Error: cannot bind to socket
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>pdns_server|pdns_recursor|pdns)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year

_ERROR_KEYWORDS = frozenset(
    ["error", "fatal", "cannot", "could not", "unable", "failed", "failure",
     "refused", "exiting", "no such"]
)
_WARN_KEYWORDS = frozenset(
    ["warning", "timeout", "unreachable", "retry", "dropping", "throttl",
     "servfail", "rejected", "exceeded"]
)


def _severity(message: str) -> Severity:
    low = message.lower()
    if low.startswith("error") or any(k in low for k in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(k in low for k in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class PowerDNSParser(LogParser):
    FORMAT_NAME = "powerdns"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "pdns" in path.name.lower():
            return True
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f'{m["month"]} {m["day"]} {_CURRENT_YEAR} {m["time"]}')
        except Exception:
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"program": m["prog"]}
        if m["pid"]:
            extra["pid"] = m["pid"]
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(message),
            source=m["prog"],
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
