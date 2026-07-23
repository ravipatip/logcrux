from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# Dovecot (IMAP/POP3/LMTP) logs ride on syslog. Tag is "dovecot", usually with
# a service sub-prefix such as imap-login:, pop3-login:, auth:, lmtp(...):
#   May 19 10:15:01 host dovecot: imap-login: Login: user=<alice>, method=PLAIN, rip=1.2.3.4
#   May 19 10:15:02 host dovecot: imap-login: Disconnected (auth failed): user=<bob>, rip=5.6.7.8
#   May 19 10:15:03 host dovecot: auth: passwd-file(eve,9.9.9.9): unknown user
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"dovecot(?:\[(?P<pid>\d+)\])?: "
    r"(?P<service>[\w()-]+): "
    r"(?P<message>.*)"
)

_USER_RE = re.compile(r"user=<([^>]*)>")
_RIP_RE = re.compile(r"rip=([0-9a-fA-F:.]+)")
_CURRENT_YEAR = datetime.now().year

_AUTH_FAIL_KEYWORDS = frozenset(
    ["auth failed", "authentication failed", "unknown user", "password mismatch",
     "disconnected (auth failed", "aborted login", "no auth attempts",
     "too many invalid commands", "login failed"]
)
_ERROR_KEYWORDS = frozenset(
    ["error", "fatal", "panic", "corrupt", "failed", "cannot", "broken",
     "no space", "out of memory"]
)


def _dovecot_severity(message: str) -> Severity:
    low = message.lower()
    if any(k in low for k in _AUTH_FAIL_KEYWORDS):
        return Severity.WARNING
    if any(k in low for k in _ERROR_KEYWORDS):
        return Severity.ERROR
    return Severity.INFO


class DovecotParser(LogParser):
    FORMAT_NAME = "dovecot"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "dovecot" in path.name.lower():
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
        service = m["service"]
        extra: dict[str, object] = {"service": service}
        if m["pid"]:
            extra["pid"] = m["pid"]
        user = _USER_RE.search(message)
        if user:
            extra["user"] = user.group(1)
        rip = _RIP_RE.search(message)
        if rip:
            extra["client_ip"] = rip.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_dovecot_severity(message),
            source="dovecot",
            message=f"{service}: {message}",
            raw=line,
            line_number=line_number,
            extra=extra,
        )
