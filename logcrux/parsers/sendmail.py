from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# Sendmail MTA logging through syslog. The classic mail-transfer log:
#   Jun 28 10:15:01 host sendmail[1234]: 1A2B3C4D: from=<a@x>, size=512, ...
#   Jun 28 10:15:02 host sm-mta[1234]: 1A2B3C4D: to=<b@y>, stat=Sent (ok)
#   Jun 28 10:15:03 host sm-mta[1234]: 1A2B3C4D: to=<b@y>, stat=Deferred: ...
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<prog>sendmail|sm-mta|sm-msp-queue|sm-client)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year

_ERROR_MARKERS = ("stat=bounced", "stat=user unknown",
                  "reject=", "lost input channel",
                  "cannot", "unable to", "did not issue",
                  "stat=service unavailable", "stat=host unknown")
_WARN_MARKERS = ("stat=queued", "deferred", "collect: premature",
                 "milter", "possible spam", "stat=expired")


def _severity(message: str) -> Severity:
    low = message.lower()
    if any(m in low for m in _ERROR_MARKERS):
        return Severity.ERROR
    if any(m in low for m in _WARN_MARKERS):
        return Severity.WARNING
    return Severity.INFO


class SendmailParser(LogParser):
    FORMAT_NAME = "sendmail"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

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
        qid = re.match(r"([0-9A-Za-z]{8,}):", message)
        if qid:
            extra["queue_id"] = qid.group(1)
        stat = re.search(r"stat=(\S+)", message)
        if stat:
            extra["stat"] = stat.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(message),
            source=m["prog"],
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
