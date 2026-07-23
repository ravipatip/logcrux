from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import TRACEBACK_CONTINUATION, LogParser, level_to_severity

# Python's stdlib logging default format:
#   2026-06-20 10:15:01,123 - myapp.module - ERROR - database connection failed
# i.e. "%(asctime)s - %(name)s - %(levelname)s - %(message)s". The comma-
# milliseconds + " - LEVEL - " spine is the distinguishing shape.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - "
    r"(?P<name>[\w.\-]+) - "
    r"(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL|EXCEPTION|NOTSET) - "
    r"(?P<message>.*)$"
)


class PyLoggingParser(LogParser):
    FORMAT_NAME = "pylogging"
    CONTINUATION = TRACEBACK_CONTINUATION

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        head = sample_lines[:20]
        matched = sum(1 for ln in head if _PATTERN.match(ln))
        # Traceback lines belong to the preceding event, so they don't count
        # against the majority gate — a log whose sample is half stack trace is
        # still a Python logging file.
        nonblank = sum(
            1 for ln in head if ln.strip() and not TRACEBACK_CONTINUATION.match(ln)
        )
        return nonblank > 0 and matched * 2 >= nonblank

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace(",", "."))
        except (ValueError, TypeError, OverflowError):
            ts = None
        level = m["level"]
        severity = (
            Severity.ERROR if level == "EXCEPTION" else level_to_severity(level)
        )
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=m["name"],
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": level.lower(), "logger": m["name"]},
        )
