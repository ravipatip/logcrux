from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Neo4j graph-database logs (debug.log / neo4j.log). Default layout is
# "ts+offset LEVEL  [logger] message":
#   2026-06-28 10:15:01.123+0000 INFO  [o.n.k.a.DbmsRuntime] Started.
#   2026-06-28 10:15:02.456+0000 WARN  [o.n.k.i.c.VmPauseMonitor] Detected VM stop
#   2026-06-28 10:15:03.789+0000 ERROR [o.n.b.r.DefaultBoltConnection] Unexpected
# The ".mmm+0000 LEVEL [o.n.…]" shape (Neo4j's abbreviated org.neo4j logger) is
# the distinctive signature.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{4}) "
    r"(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+"
    r"(?:\[(?P<logger>[^\]]+)\] )?(?P<message>.*)$"
)
_NEO4J_MARKERS = ("o.n.", "org.neo4j", "Neo4j", "neo4j", "Bolt", "DbmsRuntime",
                  "cypher", "Cypher", "database")


class Neo4jParser(LogParser):
    FORMAT_NAME = "neo4j"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:25] if _PATTERN.match(ln)]
        if not matched:
            return False
        return any(mk in ln for ln in matched for mk in _NEO4J_MARKERS)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        extra: dict[str, object] = {"level": m["level"].lower()}
        if m["logger"]:
            extra["logger"] = m["logger"]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="neo4j",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
