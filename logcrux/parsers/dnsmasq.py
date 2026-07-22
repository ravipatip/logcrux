from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# dnsmasq rides on syslog. Program tag is dnsmasq, dnsmasq-dhcp or dnsmasq-tftp:
#   Jun 20 10:23:45 host dnsmasq[1234]: query[A] example.com from 10.0.0.5
#   Jun 20 10:23:45 host dnsmasq[1234]: reply example.com is 93.184.216.34
#   Jun 20 10:23:45 host dnsmasq-dhcp[1234]: DHCPACK(eth0) 10.0.0.50 00:0c:29:aa:bb:cc host
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>dnsmasq(?:-dhcp|-tftp|-script)?)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

_QUERY_RE = re.compile(r"^query\[(?P<qtype>[A-Z0-9]+)\]\s+(?P<domain>\S+)")
_CURRENT_YEAR = datetime.now().year

# Conditions a DNS/DHCP operator cares about.
_ERROR_KEYWORDS = frozenset([
    "no servers", "failed to", "cannot", "not found", "no address",
    "refused", "config error", "bad address", "duplicate", "overflow",
    "no free addresses", "nak", "unreachable",
])
_WARN_KEYWORDS = frozenset([
    "possible dns-rebind", "reducing dns packet size", "ignoring query",
    "maximum number of concurrent dns queries reached", "dhcprelease",
])


def _dnsmasq_severity(message: str) -> Severity:
    low = message.lower()
    if any(kw in low for kw in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(kw in low for kw in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class DnsmasqParser(LogParser):
    FORMAT_NAME = "dnsmasq"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "dnsmasq" in path.name.lower():
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
        q = _QUERY_RE.match(message)
        if q:
            extra["query_type"] = q["qtype"]
            extra["domain"] = q["domain"]
        return ParsedEvent(
            timestamp=ts,
            severity=_dnsmasq_severity(message),
            source="dnsmasq",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
