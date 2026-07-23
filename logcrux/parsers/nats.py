from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# NATS server log:
#   [1] 2026/06/20 10:15:01.123456 [INF] Starting nats-server
#   [1] 2026/06/20 10:15:02.000000 [ERR] Error accepting client connection
#   [1] 2026/06/20 10:15:03.000000 [WRN] 1.2.3.4 - cid:5 - authentication error
_PATTERN = re.compile(
    r"^\[(?P<pid>\d+)\] "
    r"(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) "
    r"\[(?P<level>INF|DBG|WRN|ERR|FTL|TRC)\] (?P<message>.*)$"
)
_LEVEL_MAP = {
    "TRC": Severity.DEBUG,
    "DBG": Severity.DEBUG,
    "INF": Severity.INFO,
    "WRN": Severity.WARNING,
    "ERR": Severity.ERROR,
    "FTL": Severity.CRITICAL,
}


class NatsParser(LogParser):
    FORMAT_NAME = "nats"

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
            ts = dateparser.parse(m["ts"].replace("/", "-", 2))
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="nats",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"].lower(), "pid": m["pid"]},
        )
