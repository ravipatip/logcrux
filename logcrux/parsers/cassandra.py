from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Apache Cassandra system.log / debug.log (logback). The level comes *first*,
# then the thread, then the timestamp and source location — distinct from the
# generic "[thread] LEVEL logger" log4j order:
#   INFO  [main] 2026-06-20 10:15:01,123 StorageService.java:1234 - Node up
#   WARN  [GossipTasks:1] 2026-06-20 10:15:02,456 FailureDetector.java:288 - ...
#   ERROR [MutationStage-1] 2026-06-20 10:15:03,789 JVMStabilityInspector.java:1 - oom
_PATTERN = re.compile(
    r"^(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"\[(?P<thread>[^\]]+)\]\s+"
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+"
    r"(?P<src>[\w$.]+\.java:\d+)\s+-\s+(?P<message>.*)$"
)


class CassandraParser(LogParser):
    FORMAT_NAME = "cassandra"

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
            source="cassandra",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"].lower(), "thread": m["thread"], "src": m["src"]},
        )
