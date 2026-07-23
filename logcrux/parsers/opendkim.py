from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# OpenDKIM mail-signing/verification milter syslog output. Tagged "opendkim":
#   Jun 28 10:15:01 host opendkim[1234]: OpenDKIM filter starting
#   Jun 28 10:15:02 host opendkim[1234]: 5SAF1234: DKIM-Signature field added
#   Jun 28 10:15:03 host opendkim[1234]: 5SAF1235: bad signature data
#   Jun 28 10:15:04 host opendkim[1234]: 5SAF1236: key retrieval failed
# The "opendkim[pid]: <qid>: <verdict>" syslog tag shape is the signature.
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) opendkim\[(?P<pid>\d+)\]: (?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year
_ERROR_KW = ("failed", "error", "bad signature", "cannot", "unable", "refused",
             "no key", "verification failed")
_WARN_KW = ("not signed", "no signature", "unsigned", "skipping", "temporary")


class OpenDKIMParser(LogParser):
    FORMAT_NAME = "opendkim"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}")
        except Exception:
            ts = None
        message = m["message"].strip()
        low = message.lower()
        severity = Severity.INFO
        if any(k in low for k in _WARN_KW):
            severity = Severity.WARNING
        if any(k in low for k in _ERROR_KW):
            severity = Severity.ERROR
        extra: dict[str, object] = {"pid": m["pid"]}
        qid_m = re.match(r"([A-Za-z0-9]{6,}):", message)
        if qid_m:
            extra["queue_id"] = qid_m.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="opendkim",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
