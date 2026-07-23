from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# BIND9 (named) supports two common layouts.
#
# A) syslog-tagged (default when logging to syslog):
#    May 19 10:15:01 host named[1234]: zone example.com/IN: loaded serial 2024010101
#    May 19 10:15:02 host named[1234]: client @0x.. 1.2.3.4#54321 (a.com): query (cache) denied
#
# B) native category channel (named.conf "print-time yes; print-category yes; print-severity yes"):
#    19-May-2024 10:15:01.123 query-errors: info: client 1.2.3.4#5 (a.com): query failed (SERVFAIL)
_SYSLOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"named(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)
_NATIVE_PATTERN = re.compile(
    r"(?P<ts>\d{1,2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?) "
    r"(?P<category>[\w-]+): "
    r"(?:(?P<severity>debug|info|notice|warning|error|critical)(?:\s\(\d+\))?: )?"
    r"(?P<message>.*)"
)

_DETECT_NATIVE = re.compile(
    r"\d{1,2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}.*?"
    r"\b(?:query|zone|general|security|lame-servers|resolver)"
)
_CLIENT_IP_RE = re.compile(r"client (?:@0x[0-9a-f]+ )?(\d{1,3}(?:\.\d{1,3}){3})#\d+")
_CURRENT_YEAR = datetime.now().year

_NATIVE_SEV: dict[str, Severity] = {
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "notice": Severity.INFO,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "critical": Severity.CRITICAL,
}
_ERROR_KEYWORDS = frozenset(
    ["servfail", "lame server", "broken trust chain", "unable to", "failed",
     "no valid", "network unreachable", "host unreachable", "rejected",
     "could not", "out of memory", "too many"]
)
_WARN_KEYWORDS = frozenset(
    ["denied", "refused", "timed out", "timeout", "retry", "not authoritative",
     "duplicate", "deprecated", "exceeded"]
)


def _msg_severity(message: str) -> Severity:
    low = message.lower()
    if any(k in low for k in _ERROR_KEYWORDS):
        return Severity.ERROR
    if any(k in low for k in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class NamedParser(LogParser):
    FORMAT_NAME = "named"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            name = path.name.lower()
            if "named" in name or "bind" in name:
                return True
        if any(_DETECT_NATIVE.match(line) for line in sample_lines[:10]):
            return True
        return syslog_tag_dominant(sample_lines, _SYSLOG_PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _SYSLOG_PATTERN.match(line)
        if m:
            return self._make_syslog(m, line, line_number)
        m = _NATIVE_PATTERN.match(line)
        if m:
            return self._make_native(m, line, line_number)
        return None

    def _make_syslog(self, m: re.Match[str], line: str, line_number: int) -> ParsedEvent:
        try:
            ts = dateparser.parse(
                f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}"
            )
        except Exception:
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {}
        if m["pid"]:
            extra["pid"] = m["pid"]
        ip = _CLIENT_IP_RE.search(message)
        if ip:
            extra["client_ip"] = ip.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_msg_severity(message),
            source="named",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )

    def _make_native(self, m: re.Match[str], line: str, line_number: int) -> ParsedEvent:
        try:
            ts = dateparser.parse(m["ts"].replace("-", " "), fuzzy=True)
        except Exception:
            ts = None
        message = m["message"].strip()
        category = m["category"]
        sev_word = (m["severity"] or "").lower()
        severity = _NATIVE_SEV.get(sev_word) if sev_word else None
        if severity is None:
            severity = _msg_severity(message)
        extra: dict[str, object] = {"category": category}
        ip = _CLIENT_IP_RE.search(message)
        if ip:
            extra["client_ip"] = ip.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="named",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
