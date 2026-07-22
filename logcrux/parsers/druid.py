from __future__ import annotations

from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity, log4j_classic_fields

# Apache Druid logs (broker / historical / coordinator / middlemanager). Log4j
# shape gated on Druid vocabulary so it never poaches a plain log4j log:
#   2026-06-28 10:15:01,123 INFO [main] org.apache.druid.cli.CliBroker - Starting
#   2026-06-28 10:15:02,234 WARN [qtp-1] org.apache.druid.server.QueryResource - slow
#   2026-06-28 10:15:03,345 ERROR [coordinator] org.apache.druid.metadata... - failed
_MARKERS = ("druid", "Druid", "org.apache.druid", "io.druid")


class DruidParser(LogParser):
    FORMAT_NAME = "druid"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:25] if log4j_classic_fields(ln)]
        if not matched:
            return False
        return any(mk in ln for ln in matched for mk in _MARKERS)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        f = log4j_classic_fields(line)
        if not f:
            return None
        try:
            ts = dateparser.parse(f["ts"].replace(",", "."))  # type: ignore[union-attr]
        except (ValueError, TypeError, OverflowError):
            ts = None
        extra: dict[str, object] = {"level": f["level"].lower()}  # type: ignore[union-attr]
        if f["thread"]:
            extra["thread"] = f["thread"]
        if f["logger"]:
            extra["logger"] = f["logger"]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(f["level"]),
            source="druid",
            message=f["message"] or "",
            raw=line,
            line_number=line_number,
            extra=extra,
        )
