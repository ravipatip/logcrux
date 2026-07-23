from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Cisco ASA / FTD / PIX / FWSM firewall syslog. The hallmark is the
# "%ASA-<sev>-<msgid>:" tag, optionally behind a syslog/date header:
#   %ASA-6-302013: Built outbound TCP connection 12345 for outside:...
#   Jun 20 2026 10:15:01 fw1 : %ASA-4-106023: Deny tcp src outside:1.2.3.4/55000
#   %FTD-1-199010: Signature ... matched
# The digit between the family and the message-id is the syslog severity (0-7).
_TAG_RE = re.compile(
    r"%(?P<family>ASA|FTD|PIX|FWSM|ACE)-(?P<sev>\d)-(?P<msgid>\d+):\s*(?P<message>.*)$"
)
# Optional leading timestamp: "Jun 20 2026 10:15:01" or "Jun 20 10:15:01".
_TS_RE = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2}(?:\s+\d{4})? \d{2}:\d{2}:\d{2})")

_SEV_MAP = {
    "0": Severity.CRITICAL,
    "1": Severity.CRITICAL,
    "2": Severity.CRITICAL,
    "3": Severity.ERROR,
    "4": Severity.WARNING,
    "5": Severity.INFO,
    "6": Severity.INFO,
    "7": Severity.DEBUG,
}


class CiscoASAParser(LogParser):
    FORMAT_NAME = "ciscoasa"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _TAG_RE.search(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _TAG_RE.search(line)
        if not m:
            return None
        ts = None
        tm = _TS_RE.match(line)
        if tm:
            raw_ts = tm["ts"]
            if not re.search(r"\d{4}", raw_ts):
                raw_ts = f"{raw_ts} {datetime.now().year}"
            try:
                ts = dateparser.parse(raw_ts)
            except (ValueError, TypeError, OverflowError):
                ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_SEV_MAP.get(m["sev"], Severity.INFO),
            source=f"cisco-{m['family'].lower()}",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"msg_id": m["msgid"], "syslog_severity": int(m["sev"])},
        )
