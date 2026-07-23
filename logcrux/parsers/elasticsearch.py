from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Elasticsearch (log4j2) server log format:
#   [2024-06-20T10:23:45,123][INFO ][o.e.n.Node           ] [node-1] starting ...
#   [2024-06-20T10:23:45,123][WARN ][o.e.c.r.a.DiskThresholdMonitor] [node-1] \
#       high disk watermark [90%] exceeded on [abc][/data] free: 5gb[8%]
_PATTERN = re.compile(
    r"\[(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d+)\]"
    r"\[(?P<level>[A-Z]+)\s*\]"
    r"\[(?P<logger>[^\]]+)\]"
    r"(?:\s*\[(?P<node>[^\]]+)\])?"
    r"\s*(?P<message>.*)"
)

_LEVEL_MAP: dict[str, Severity] = {
    "TRACE": Severity.DEBUG,
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARN": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "FATAL": Severity.CRITICAL,
}


class ElasticsearchParser(LogParser):
    FORMAT_NAME = "elasticsearch"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        name = path.name.lower() if path else ""
        if "elasticsearch" in name or "opensearch" in name:
            return True
        # ISO-8601 timestamp with a 'T' inside the first bracket distinguishes
        # Elasticsearch from Kafka (which uses a space-separated date).
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
        extra: dict[str, object] = {"logger": m["logger"].strip()}
        if m["node"]:
            extra["node"] = m["node"].strip()
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="elasticsearch",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
