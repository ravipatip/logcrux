from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Celery (Python distributed task queue) default log format:
#   [2026-06-20 10:23:45,123: WARNING/MainProcess] Substantial drift detected
#   [2026-06-20 10:23:45,123: INFO/MainProcess] Task app.add[abc] succeeded in 0.01s
#   [2026-06-20 10:23:45,123: ERROR/ForkPoolWorker-2] Task app.add[abc] raised: ...
#   [2026-06-20 10:23:45,123: CRITICAL/MainProcess] Unrecoverable error: ...
_PATTERN = re.compile(
    r"\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}): "
    r"(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL|FATAL)/"
    r"(?P<process>[\w\-]+)\] "
    r"(?P<message>.*)"
)

_TASK_RE = re.compile(r"Task (?P<task>[\w.]+)\[(?P<id>[^\]]+)\]")

_LEVEL_MAP: dict[str, Severity] = {
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "CRITICAL": Severity.CRITICAL,
    "FATAL": Severity.CRITICAL,
}


class CeleryParser(LogParser):
    FORMAT_NAME = "celery"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "celery" in str(path).lower():
            return True
        return any(_PATTERN.match(line) for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace(",", "."))
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {
            "level": m["level"],
            "process": m["process"],
        }
        task = _TASK_RE.search(message)
        if task:
            extra["task"] = task["task"]
            extra["task_id"] = task["id"]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="celery",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
