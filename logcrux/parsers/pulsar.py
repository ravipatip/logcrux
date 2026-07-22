from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Apache Pulsar (broker / bookie / zookeeper) Log4j2 default layout. A leading
# ISO-8601 timestamp with millis+offset distinguishes it from a bare Log4j line:
#   2026-06-20T10:15:01,123+0000 [pulsar-web-1] INFO  o.a.p.broker.PulsarService - Created ns
#   2026-06-20T10:15:02,456+0000 [bookie-io-1] WARN  o.a.bookkeeper.proto - Error reading entry
#   2026-06-20T10:15:03,789+0000 [main] ERROR o.a.p.broker.PulsarService - Failed to start broker
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d{3}[+\-]\d{4}) "
    r"\[(?P<thread>[^\]]+)\] "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"(?P<logger>\S+) - (?P<message>.*)$"
)


class PulsarParser(LogParser):
    FORMAT_NAME = "pulsar"

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
            ts = dateparser.parse(m["ts"].replace(",", ".", 1))
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="pulsar",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"].lower(), "thread": m["thread"], "logger": m["logger"]},
        )
