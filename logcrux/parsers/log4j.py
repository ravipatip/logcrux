from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import TRACEBACK_CONTINUATION, LogParser, level_to_severity

# Log4j / Logback default pattern (also Cassandra, Solr, Spark, Flink, ...):
#   2026-06-20 10:15:01,123 [main] INFO  com.example.App - server started
#   2026-06-20 10:15:01.123 [pool-1] ERROR c.e.Svc - connection refused
# Shape: ISO datetime (comma or dot millis) + [thread] + LEVEL (padded) +
# dotted.logger + " - " + message.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[,.]\d{3}) "
    r"\[(?P<thread>[^\]]+)\] "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL) +"
    r"(?P<logger>\S+) - (?P<message>.*)$"
)


class Log4jParser(LogParser):
    FORMAT_NAME = "log4j"
    CONTINUATION = TRACEBACK_CONTINUATION

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        head = sample_lines[:20]
        matched = sum(1 for ln in head if _PATTERN.match(ln))
        # Java stack traces ("\tat com...", "Caused by:") belong to the
        # preceding event and don't count against the majority gate.
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
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source=m["logger"],
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": level.lower(), "thread": m["thread"], "logger": m["logger"]},
        )
