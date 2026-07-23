from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# MikroTik RouterOS remote-syslog output. After the syslog header RouterOS emits
# comma-joined topics where one topic is the severity, then the message:
#   Jun 28 10:15:01 192.168.88.1 system,info,account user admin logged in
#   Jun 28 10:15:02 192.168.88.1 firewall,info forward: in:ether1 out:ether2
#   Jun 28 10:15:03 192.168.88.1 dhcp,critical lease assign failed
# The "<topic>,...,<severity-topic> message" group is the RouterOS signature.
_SEV_TOPICS = {
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "critical": Severity.CRITICAL,
}
_TOPIC = (
    r"system|firewall|dhcp|dns|wireless|interface|ppp|route|script|account|"
    r"info|warning|error|critical|debug|l2tp|ovpn|ipsec|hotspot|radius|ntp|"
    r"manager|web-proxy|bgp|ospf|snmp|read|write|packet|raw|caps|wireguard"
)
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<topics>(?:" + _TOPIC + r")(?:,(?:" + _TOPIC + r"|[\w-]+))+) "
    r"(?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year


class MikroTikParser(LogParser):
    FORMAT_NAME = "mikrotik"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        # Require the comma-joined topic group with at least one severity topic
        # so a plain syslog message cannot be mistaken for RouterOS output.
        hits = 0
        for ln in sample_lines[:25]:
            m = _PATTERN.match(ln)
            if m and any(t in _SEV_TOPICS for t in m["topics"].split(",")):
                hits += 1
        return hits > 0 and hits * 2 >= sum(
            1 for ln in sample_lines[:25] if ln.strip()
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        topics = m["topics"].split(",")
        if not any(t in _SEV_TOPICS for t in topics):
            return None
        try:
            ts = dateparser.parse(f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}")
        except Exception:
            ts = None
        severity = Severity.INFO
        for t in topics:
            if t in _SEV_TOPICS:
                severity = level_to_severity(t, _SEV_TOPICS[t])
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="mikrotik",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"topics": m["topics"]},
        )
