from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# PgBouncer (PostgreSQL connection pooler) log:
#   2026-06-20 10:15:01.123 UTC [1234] LOG C-0x55: db/user@1.2.3.4:5432 login attempt
#   2026-06-20 10:15:02.000 UTC [1234] WARNING C-0x55: pooler error
#   2026-06-20 10:15:03.000 UTC [1234] ERROR S-0x77: server login failed
# Unlike PostgreSQL ("LEVEL:  message"), pgbouncer writes "LEVEL message" with no
# colon and the message typically begins with a C-/S-/stats connection token.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) (?P<tz>\w+) "
    r"\[(?P<pid>\d+)\] "
    r"(?P<level>LOG|INFO|WARNING|ERROR|FATAL|DEBUG|NOISE) (?P<message>.*)$"
)
_LEVEL_MAP = {
    "NOISE": Severity.DEBUG,
    "DEBUG": Severity.DEBUG,
    "LOG": Severity.INFO,
    "INFO": Severity.INFO,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "FATAL": Severity.CRITICAL,
}
# pgbouncer messages characteristically start with these connection markers.
_MSG_MARKERS = ("C-0x", "C-", "S-0x", "S-", "stats:", "kernel file",
                "pooler error", "login attempt", "closing because")


class PgBouncerParser(LogParser):
    FORMAT_NAME = "pgbouncer"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "pgbouncer" in str(path).lower():
            return True
        for ln in sample_lines[:20]:
            m = _PATTERN.match(ln)
            if m and m["message"].lstrip().startswith(_MSG_MARKERS):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f'{m["ts"]} {m["tz"]}')
        except (ValueError, TypeError, OverflowError):
            try:
                ts = dateparser.parse(m["ts"])
            except (ValueError, TypeError, OverflowError):
                ts = None
        level = m["level"]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(level, Severity.INFO),
            source="pgbouncer",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": level.lower(), "pid": m["pid"]},
        )
