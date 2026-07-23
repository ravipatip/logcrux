from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# strongSwan IPsec daemon (charon) logs through syslog. Program tags:
#   charon, charon-systemd, ipsec, starter
#   Jun 20 10:23:45 host charon[1234]: 09[IKE] establishing IKE_SA failed, \
#       peer not responding
#   Jun 20 10:23:45 host charon[1234]: 12[NET] sending packet: from 1.2.3.4 to 5.6.7.8
#   Jun 20 10:23:45 host charon[1234]: 05[IKE] CHILD_SA net{2} established
# Messages carry an optional "NN[SUB]" thread/subsystem prefix.
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>charon(?:-systemd)?|ipsec|starter)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

_SUB_RE = re.compile(r"^(?P<thread>\d+)\[(?P<sub>[A-Z]{3})\]\s*")
_CURRENT_YEAR = datetime.now().year

_ERROR_KEYWORDS = frozenset([
    "failed", "no proposal chosen", "authentication failed", "unable to",
    "giving up", "no route", "no shared key", "deleting", "destroying",
    "fatal", "no matching", "could not", "invalid", "no acceptable",
    "tried to check signature", "constraint check failed",
])
_WARN_KEYWORDS = frozenset([
    "retransmit", "peer not responding", "rekey", "reauth",
    "received delete", "received notify error", "timeout", "no traffic",
    "dpd", "received retransmit",
])


def _strongswan_severity(message: str) -> Severity:
    low = message.lower()
    if any(kw in low for kw in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(kw in low for kw in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class StrongSwanParser(LogParser):
    FORMAT_NAME = "strongswan"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            name = path.name.lower()
            if "strongswan" in name or "charon" in name or "ipsec" in name:
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
        raw_message = m["message"].strip()
        severity = _strongswan_severity(raw_message)
        extra: dict[str, object] = {"program": m["prog"]}
        if m["pid"]:
            extra["pid"] = m["pid"]
        sub = _SUB_RE.match(raw_message)
        message = raw_message
        if sub:
            extra["subsystem"] = sub["sub"]
            message = _SUB_RE.sub("", raw_message)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=m["prog"],
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
