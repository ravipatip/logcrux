from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# OpenVPN native log format uses a C ctime() prefix (weekday + year at end):
#   Thu Jun 20 10:23:45 2024 TLS Error: TLS key negotiation failed to occur within 60s
#   Thu Jun 20 10:23:45 2024 1.2.3.4:1194 VERIFY ERROR: depth=0, error=certificate expired
#   Thu Jun 20 10:23:45 2024 client/1.2.3.4:1194 SIGTERM[soft,ping-restart] received
_CTIME_PATTERN = re.compile(
    r"(?P<wday>\w{3}) (?P<mon>\w{3})\s+(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) (?P<year>\d{4}) "
    r"(?P<message>.*)"
)

# OpenVPN can also log via syslog with an openvpn / ovpn-* program tag:
#   Jun 20 10:23:45 host ovpn-server[123]: TLS Error: TLS handshake failed
_SYSLOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>openvpn|ovpn-[\w-]+)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

_CURRENT_YEAR = datetime.now().year

# Substrings OpenVPN emits that indicate a problem operators should see.
_ERROR_KEYWORDS = frozenset([
    "tls error", "verify error", "verify_error", "auth_failed",
    "cannot load", "failed", "fatal", "cannot resolve", "connection reset",
    "tls handshake failed", "certificate expired", "no route to host",
])
_WARN_KEYWORDS = frozenset([
    "warning", "sigterm", "sigusr1", "restart", "replay-window",
    "ping-restart", "inactivity timeout", "renegotiating",
])


def _openvpn_severity(message: str) -> Severity:
    low = message.lower()
    if any(kw in low for kw in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(kw in low for kw in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class OpenVPNParser(LogParser):
    FORMAT_NAME = "openvpn"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        name = path.name.lower() if path else ""
        if "openvpn" in name or "ovpn" in name:
            return True
        # Native ctime format with OpenVPN-specific keywords, or syslog-tagged.
        ovpn_markers = ("OpenVPN", "TLS", "VERIFY", "PUSH:", "MULTI:", "TUN/TAP", "tls-crypt")
        for line in sample_lines[:10]:
            m = _CTIME_PATTERN.match(line)
            if m and any(mk in line for mk in ovpn_markers):
                return True
        return syslog_tag_dominant(sample_lines, _SYSLOG_PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _CTIME_PATTERN.match(line)
        if m:
            try:
                ts = dateparser.parse(f"{m['mon']} {m['day']} {m['year']} {m['time']}")
            except (ValueError, TypeError, OverflowError):
                ts = None
            message = m["message"].strip()
            return ParsedEvent(
                timestamp=ts,
                severity=_openvpn_severity(message),
                source="openvpn",
                message=message,
                raw=line,
                line_number=line_number,
                extra={},
            )
        m = _SYSLOG_PATTERN.match(line)
        if m:
            try:
                ts = dateparser.parse(f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}")
            except (ValueError, TypeError, OverflowError):
                ts = None
            message = m["message"].strip()
            extra: dict[str, object] = {"program": m["prog"]}
            if m["pid"]:
                extra["pid"] = m["pid"]
            return ParsedEvent(
                timestamp=ts,
                severity=_openvpn_severity(message),
                source="openvpn",
                message=message,
                raw=line,
                line_number=line_number,
                extra=extra,
            )
        return None
