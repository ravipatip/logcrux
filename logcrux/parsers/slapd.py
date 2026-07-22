from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# OpenLDAP (slapd) logs through syslog. Program tag is slapd:
#   Jun 20 10:23:45 host slapd[1234]: conn=1001 op=0 BIND dn="cn=admin,dc=x" method=128
#   Jun 20 10:23:45 host slapd[1234]: conn=1001 op=0 RESULT tag=97 err=49 text=
#   Jun 20 10:23:45 host slapd[1234]: connection_read(12): no connection!
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>slapd)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)

_ERR_RE = re.compile(r"\berr=(?P<code>\d+)")
_CONN_RE = re.compile(r"\bconn=(?P<conn>\d+)")
_CURRENT_YEAR = datetime.now().year

# Hard failures an LDAP operator cares about.
_ERROR_KEYWORDS = frozenset([
    "fatal", "cannot", "could not", "failed", "unable to", "no connection",
    "tls negotiation failure", "tls error", "denied", "deadlock",
    "ldap_back", "abandon", "corrupt", "panic", "out of memory",
])
# err= result codes that signal an operational problem (not benign 0/no-such).
_WARN_KEYWORDS = frozenset([
    "size limit exceeded", "time limit exceeded", "admin limit",
    "no such object", "constraint violation", "already exists",
    "busy", "unavailable", "unwilling to perform", "deprecated",
])


def _slapd_severity(message: str) -> Severity:
    low = message.lower()
    if any(kw in low for kw in _ERROR_KEYWORDS):
        return Severity.ERROR
    m = _ERR_RE.search(message)
    if m:
        code = int(m["code"])
        # err=49 invalid credentials is a recurrent auth-failure signal.
        if code == 49:
            return Severity.WARNING
        if code != 0:
            return Severity.WARNING
    if any(kw in low for kw in _WARN_KEYWORDS):
        return Severity.WARNING
    return Severity.INFO


class SlapdParser(LogParser):
    FORMAT_NAME = "slapd"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            name = path.name.lower()
            if "slapd" in name or "openldap" in name:
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
        extra: dict[str, object] = {"program": "slapd"}
        if m["pid"]:
            extra["pid"] = m["pid"]
        conn = _CONN_RE.search(message)
        if conn:
            extra["conn"] = conn["conn"]
        err = _ERR_RE.search(message)
        if err:
            extra["err"] = err["code"]
        return ParsedEvent(
            timestamp=ts,
            severity=_slapd_severity(message),
            source="slapd",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
