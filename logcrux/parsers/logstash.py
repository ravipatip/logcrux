from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Logstash (log4j2) server log. Shares the Elasticsearch "[ts][LEVEL][logger]"
# bracket shape, so it is distinguished by its always-"logstash.*" logger and
# must be checked before the Elasticsearch parser:
#   [2026-06-20T10:15:01,123][INFO ][logstash.agent           ] Starting API
#   [2026-06-20T10:15:02,456][WARN ][logstash.outputs.elasticsearch] retrying
#   [2026-06-20T10:15:03,789][ERROR][logstash.javapipeline    ] Pipeline aborted
_PATTERN = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d+)\]"
    r"\[(?P<level>[A-Z]+)\s*\]"
    r"\[(?P<logger>[^\]]+)\]\s*(?P<message>.*)$"
)


class LogstashParser(LogParser):
    FORMAT_NAME = "logstash"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            m = _PATTERN.match(ln)
            if m and m["logger"].strip().startswith("logstash"):
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
            source="logstash",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"].lower(), "logger": m["logger"].strip()},
        )
