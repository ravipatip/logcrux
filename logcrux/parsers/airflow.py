from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Apache Airflow task / scheduler logs. The default formatter is
# "[ts] {source:line} LEVEL - message":
#   [2026-06-28 10:15:01,123] {taskinstance.py:1234} INFO - Marking task as SUCCESS
#   [2026-06-28 10:15:02,456] {scheduler_job.py:88} WARNING - Killing zombie task
#   [2026-06-28 10:15:03,789] {taskinstance.py:1900} ERROR - Task failed
# The "{file.py:line}" source token is the distinctive signature.
_PATTERN = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d+)?)\] "
    r"\{(?P<src>[\w./-]+:\d+)\} "
    r"(?P<level>[A-Z]+) - (?P<message>.*)$"
)


class AirflowParser(LogParser):
    FORMAT_NAME = "airflow"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

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
            source="airflow",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": level.lower(), "src": m["src"]},
        )
