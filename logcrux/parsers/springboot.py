from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import TRACEBACK_CONTINUATION, LogParser, level_to_severity

# Spring Boot / Logback default console pattern — one of the most common Java
# application logs running on Linux:
#   2026-06-23 10:23:45.123  INFO 12345 --- [           main] c.e.App  : Started
#   2026-06-23 10:23:45.123 ERROR 12345 --- [http-nio-8080-exec-1] c.e.Svc : boom
# Layout: <ts> <LEVEL> <pid> --- [<thread>] <logger> : <message>
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"(?P<pid>\d+)\s+---\s+"
    r"\[(?P<thread>[^\]]*)\]\s+"
    r"(?P<logger>\S+)\s+:\s?(?P<message>.*)$"
)


class SpringBootParser(LogParser):
    FORMAT_NAME = "springboot"
    CONTINUATION = TRACEBACK_CONTINUATION

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for line in sample_lines[:10]:
            if _PATTERN.match(line):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        ts: datetime | None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source=m["logger"],
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"], "logger": m["logger"], "thread": m["thread"].strip()},
        )
