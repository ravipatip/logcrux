from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Apache ActiveMQ (and ActiveMQ Artemis) broker log — the default Log4j layout
# uses " | " as a field separator:
#   2026-06-20 10:15:01,123 | INFO  | ActiveMQ 5.18 started | o.a.a.broker... | main
#   2026-06-20 10:15:02,456 | WARN  | Transport Connection failed | o.a.a... | Transport
#   2026-06-20 10:15:03,789 | ERROR | Failed to start broker | o.a.a.broker... | main
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) \| "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s* \| "
    r"(?P<message>.*?) \| (?P<logger>[^|]*?) \| (?P<thread>.*)$"
)


class ActiveMQParser(LogParser):
    FORMAT_NAME = "activemq"

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
            ts = dateparser.parse(m["ts"].replace(",", "."))
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="activemq",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={
                "level": m["level"].lower(),
                "logger": m["logger"].strip(),
                "thread": m["thread"].strip(),
            },
        )
