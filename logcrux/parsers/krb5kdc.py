from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# MIT Kerberos KDC / admin server (krb5kdc.log, kadmind.log). Each line is a
# syslog-style timestamp + program[pid](level): request, e.g.:
#   Jun 28 10:15:01 host krb5kdc[1234](info): AS_REQ (8 etypes) 1.2.3.4: ISSUE
#   Jun 28 10:15:02 host krb5kdc[1234](info): TGS_REQ 1.2.3.4: ISSUE ...
#   Jun 28 10:15:03 krb5kdc[1234](info): AS_REQ ... NEEDED_PREAUTH: ...
#   Jun 28 10:15:04 host kadmind[1234](Notice): ... failed to ...
# The host field is optional (file logging omits it); the (level) + KRB verb
# pair is the distinctive signature.
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?:(?P<host>\S+) )?"
    r"(?P<prog>krb5kdc|kadmind|krb524d)\[(?P<pid>\d+)\]"
    r"\((?P<level>\w+)\): "
    r"(?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year

_LEVEL_MAP = {
    "info": Severity.INFO,
    "notice": Severity.INFO,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "err": Severity.ERROR,
    "crit": Severity.CRITICAL,
}
_ERROR_MARKERS = ("failed", "error", "cannot", "no such", "denied",
                  "decrypt integrity check failed", "client not found",
                  "server not found", "preauth failed", "expired")


def _severity(level: str, message: str) -> Severity:
    base = _LEVEL_MAP.get(level.lower(), Severity.INFO)
    low = message.lower()
    if any(m in low for m in _ERROR_MARKERS):
        return Severity.ERROR
    return base


class Krb5KdcParser(LogParser):
    FORMAT_NAME = "krb5kdc"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
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
        extra: dict[str, object] = {
            "program": m["prog"],
            "pid": m["pid"],
            "level": m["level"].lower(),
        }
        verb = re.match(r"(AS_REQ|TGS_REQ|AS_REP|TGS_REP)", message)
        if verb:
            extra["request_type"] = verb.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(m["level"], message),
            source=m["prog"],
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
