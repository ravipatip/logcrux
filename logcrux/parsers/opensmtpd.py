from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# OpenSMTPD (the OpenBSD mail daemon) logging through syslog under the "smtpd"
# tag. Its report lines are space-delimited key=value with a leading verb:
#   Jun 28 10:15:01 host smtpd[1234]: 1a2b smtp connected address=1.2.3.4 ...
#   Jun 28 10:15:02 host smtpd[1234]: 1a2b smtp message msgid=... size=512 ...
#   Jun 28 10:15:03 host smtpd[1234]: 1a2b mta delivery evpid=... result="Ok"
#   Jun 28 10:15:04 host smtpd[1234]: smtp-in: Failed command: ... 550 ...
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>smtpd|smtpd-filter)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)
# Verbs/markers that distinguish OpenSMTPD from any other "smtpd"-tagged daemon.
_OSMTPD_MARKERS = ("smtp connected", "smtp disconnected", "smtp message",
                   "smtp failed-command", "smtp tls", "smtp bad-input",
                   "mta delivery", "mta connecting", "mta connected",
                   "mta error", "mta tls", "smtp-in", "smtp-out",
                   "queue:", "scheduler:", "filter-", "report ")
_CURRENT_YEAR = datetime.now().year


def _severity(message: str) -> Severity:
    low = message.lower()
    if ("result=\"permfail" in low or "result=permfail" in low
            or "mta error" in low or "failed" in low or "bad-input" in low
            or "delivery evpid" in low and "tempfail" in low):
        return Severity.ERROR
    if ("result=\"tempfail" in low or "result=tempfail" in low
            or "disconnected" in low and "reason=" in low or "timeout" in low):
        return Severity.WARNING
    return Severity.INFO


class OpenSMTPDParser(LogParser):
    FORMAT_NAME = "opensmtpd"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if not syslog_tag_dominant(sample_lines, _PATTERN, path=path):
            return False
        # Require an OpenSMTPD-specific verb so a generic "smtpd"-tagged log
        # (e.g. another mailer) isn't hijacked.
        return any(
            mk in ln.lower() for ln in sample_lines[:20] for mk in _OSMTPD_MARKERS
        )

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
        extra: dict[str, object] = {"program": m["prog"]}
        if m["pid"]:
            extra["pid"] = m["pid"]
        result = re.search(r'result="?([A-Za-z]+)', message)
        if result:
            extra["result"] = result.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(message),
            source="opensmtpd",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
