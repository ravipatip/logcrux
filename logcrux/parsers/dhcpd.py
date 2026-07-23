from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# ISC dhcpd / dhclient logs ride on syslog. Program tag is dhcpd / dhclient.
#   May 19 10:15:01 host dhcpd[1234]: DHCPDISCOVER from 00:0c:29:aa:bb:cc via eth0
#   May 19 10:15:01 host dhcpd[1234]: DHCPOFFER on 10.0.0.50 to 00:0c:29:aa:bb:cc via eth0
#   May 19 10:15:02 host dhcpd[1234]: DHCPNAK on 10.0.0.99 to 00:0c:29:aa:bb:cc via eth0
#   May 19 10:15:03 host dhcpd[1234]: no free leases on subnet 10.0.0.0/24
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>dhcpd|dhclient|dhcrelay)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

# Leading DHCP message type (DHCPDISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE/...)
_MSGTYPE_RE = re.compile(r"^(?P<mtype>DHCP[A-Z]+)\b")
_MAC_RE = re.compile(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b")
_CURRENT_YEAR = datetime.now().year

# Lease-exhaustion / failure conditions that operators care about.
_ERROR_KEYWORDS = frozenset(
    ["no free leases", "peer holds all free leases", "ICMP echo reply",
     "not authoritative", "unable to", "failed", "can't", "abandoned",
     "network is unreachable", "no subnet declaration"]
)
_WARN_TYPES = frozenset(["DHCPNAK", "DHCPDECLINE"])


def _dhcpd_severity(mtype: str, message: str) -> Severity:
    low = message.lower()
    if any(k in low for k in _ERROR_KEYWORDS):
        return Severity.ERROR
    if mtype in _WARN_TYPES or "abandon" in low:
        return Severity.WARNING
    return Severity.INFO


class DhcpdParser(LogParser):
    FORMAT_NAME = "dhcpd"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "dhcp" in path.name.lower():
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
        mtype = ""
        mt = _MSGTYPE_RE.match(message)
        if mt:
            mtype = mt["mtype"]
            extra["msg_type"] = mtype
        mac = _MAC_RE.search(message)
        if mac:
            extra["mac"] = mac.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_dhcpd_severity(mtype, message),
            source="dhcpd",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
