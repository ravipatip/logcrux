from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Patroni (PostgreSQL HA template) log. Python-logging style but with the level
# attached to a colon and no logger field — the cluster-management chatter:
#   2026-06-20 10:15:01,123 INFO: no action. I am (node1), the leader with the lock
#   2026-06-20 10:15:02,456 WARNING: Postgresql is not running.
#   2026-06-20 10:15:03,789 ERROR: get_postgresql_status failed
# The shape is fairly generic, so detection requires a clear majority of the
# sample to match (a stray line can't hijack the file).
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) "
    r"(?P<level>INFO|WARNING|ERROR|CRITICAL|DEBUG): (?P<message>.*)$"
)


class PatroniParser(LogParser):
    FORMAT_NAME = "patroni"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "patroni" in path.name.lower():
            return True
        candidates = [ln for ln in sample_lines[:20] if ln.strip()]
        if not candidates:
            return False
        matched = sum(1 for ln in candidates if _PATTERN.match(ln))
        return matched > 0 and matched * 2 >= len(candidates)

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
            source="patroni",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"].lower()},
        )
