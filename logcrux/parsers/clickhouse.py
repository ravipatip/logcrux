from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# ClickHouse server log. Distinctive dotted date + thread + query-id + a
# <Level> tag in angle brackets:
#   2026.06.20 10:15:01.123456 [ 12345 ] {query-id} <Error> executeQuery: Code: 60
#   2026.06.20 10:15:02.000000 [ 100 ] {} <Information> Application: Ready
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"\[ (?P<thread>\d+) \] "
    r"\{(?P<query>[^}]*)\} "
    r"<(?P<level>Trace|Debug|Information|Notice|Warning|Error|Fatal|Test)> "
    r"(?P<message>.*)$"
)
_LEVEL_MAP = {
    "test": Severity.DEBUG,
    "trace": Severity.DEBUG,
    "debug": Severity.DEBUG,
    "information": Severity.INFO,
    "notice": Severity.INFO,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "fatal": Severity.CRITICAL,
}


class ClickHouseParser(LogParser):
    FORMAT_NAME = "clickhouse"

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
            ts = dateparser.parse(m["ts"].replace(".", "-", 2))
        except (ValueError, TypeError, OverflowError):
            ts = None
        extra: dict[str, object] = {"level": m["level"].lower(), "thread": m["thread"]}
        if m["query"]:
            extra["query_id"] = m["query"]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"].lower(), Severity.INFO),
            source="clickhouse",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
