from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Asterisk PBX full/messages log:
#   [Jun 20 10:15:01] NOTICE[1234] chan_sip.c: Registration from '...' failed
#   [Jun 20 10:15:02] WARNING[1234][C-00000001] app_dial.c: Unable to create channel
#   [Jun 20 10:15:03] ERROR[1234] pbx.c: Error parsing dialplan
#   [Jun 20 10:15:04] VERBOSE[1234] -- Executing Dial
_PATTERN = re.compile(
    r"^\[(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})\] "
    r"(?P<level>VERBOSE|DEBUG|NOTICE|WARNING|ERROR|DTMF|FAX|SECURITY)"
    r"\[(?P<thread>\d+)\](?:\[(?P<call>[^\]]+)\])? "
    r"(?P<message>.*)$"
)
_LEVEL_MAP = {
    "DEBUG": Severity.DEBUG,
    "VERBOSE": Severity.INFO,
    "DTMF": Severity.INFO,
    "FAX": Severity.INFO,
    "NOTICE": Severity.INFO,
    "SECURITY": Severity.WARNING,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
}
_CURRENT_YEAR = datetime.now().year


class AsteriskParser(LogParser):
    FORMAT_NAME = "asterisk"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _PATTERN.match(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f'{m["ts"]} {_CURRENT_YEAR}')
        except (ValueError, TypeError, OverflowError):
            ts = None
        level = m["level"]
        extra: dict[str, object] = {"level": level.lower(), "thread": m["thread"]}
        if m["call"]:
            extra["call_id"] = m["call"]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(level, Severity.INFO),
            source="asterisk",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
