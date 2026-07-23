from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Gunicorn (Python WSGI) error/access log format:
#   [2024-06-20 10:23:45 +0000] [123] [INFO] Starting gunicorn 21.2.0
#   [2024-06-20 10:23:45 +0000] [456] [ERROR] Worker (pid:789) was sent SIGKILL! \
#       Perhaps out of memory?
#   [2024-06-20 10:23:45 +0000] [123] [CRITICAL] WORKER TIMEOUT (pid:789)
_PATTERN = re.compile(
    r"\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: [+-]\d{4})?)\] "
    r"\[(?P<pid>\d+)\] "
    r"\[(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\] "
    r"(?P<message>.*)"
)

_LEVEL_MAP: dict[str, Severity] = {
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "CRITICAL": Severity.CRITICAL,
}


class GunicornParser(LogParser):
    FORMAT_NAME = "gunicorn"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "gunicorn" in path.name.lower():
            return True
        return any(_PATTERN.match(line) for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="gunicorn",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"pid": m["pid"]},
        )
