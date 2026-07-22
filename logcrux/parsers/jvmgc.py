from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# JVM unified logging (JEP 158, JDK 9+) garbage-collection log. Each line is a
# series of "[decorator]" tags — timestamp/uptime, level, and tag-set — then the
# message:
#   [2026-06-28T10:15:01.123+0000][info][gc] GC(0) Pause Young (Normal) 24M->8M
#   [12.345s][info][gc,heap] GC(3) Eden regions: 10->0
#   [2026-06-28T10:15:03.789+0000][warning][gc,alloc] Allocation stall
# Distinguished by a "[gc...]" tag decorator (the gc selector is the signature).
_PATTERN = re.compile(
    r"^\[(?P<ts>[^\]]+)\]"                       # time or uptime decorator
    r"(?:\[(?P<level>trace|debug|info|warning|error)\s*\])?"
    r"\[(?P<tags>[\w,=:+-]*gc[\w,=:+-]*)\] "      # tag-set containing "gc"
    r"(?P<message>.*)$"
)


class JvmGcParser(LogParser):
    FORMAT_NAME = "jvmgc"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        ts = None
        raw_ts = m["ts"]
        # Absolute ISO timestamps parse directly; "[12.345s]" uptime stamps do
        # not encode a wall-clock time, so leave ts None for those.
        if re.match(r"\d{4}-\d{2}-\d{2}T", raw_ts):
            try:
                ts = dateparser.parse(raw_ts)
            except (ValueError, TypeError, OverflowError):
                ts = None
        level = m["level"] or "info"
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source="jvm-gc",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": level, "tags": m["tags"]},
        )
