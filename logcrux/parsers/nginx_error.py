from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.apache_error import _LEVEL_MAP
from logcrux.parsers.base import LogParser

_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
    r"\[(?P<level>\w+)\] "
    r"(?P<pid>\d+)#\d+: "
    r"(?P<message>.*)"
)


class NginxErrorParser(LogParser):
    FORMAT_NAME = "nginx-error"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "nginx" in str(path) and "error" in path.name:
            return True
        return any(_PATTERN.match(line) for line in sample_lines[:5])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["timestamp"])
        except Exception:
            ts = None
        level = m["level"].lower()
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(level, Severity.UNKNOWN),
            source="nginx",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"pid": m["pid"]},
        )
