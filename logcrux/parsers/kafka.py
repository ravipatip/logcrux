from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Apache Kafka (log4j) server.log format:
#   [2024-06-20 10:23:45,123] INFO [KafkaServer id=0] started (kafka.server.KafkaServer)
#   [2024-06-20 10:23:45,123] ERROR [ReplicaManager broker=1] Error processing fetch \
#       (kafka.server.ReplicaManager)
# A space-separated date (no 'T') distinguishes Kafka from Elasticsearch.
_PATTERN = re.compile(
    r"\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\] "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL) "
    r"(?P<message>.*?)"
    r"(?:\s*\((?P<logger>[\w.$]+)\))?$"
)

_LEVEL_MAP: dict[str, Severity] = {
    "TRACE": Severity.DEBUG,
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARN": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "FATAL": Severity.CRITICAL,
}


class KafkaParser(LogParser):
    FORMAT_NAME = "kafka"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        name = path.name.lower() if path else ""
        if "kafka" in name or name in ("server.log", "controller.log", "state-change.log"):
            # Only accept a Kafka-ish filename when content also matches, so a
            # generic server.log isn't hijacked.
            if any(_PATTERN.match(line) for line in sample_lines[:10]):
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
        extra: dict[str, object] = {}
        if m["logger"]:
            extra["logger"] = m["logger"]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="kafka",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
