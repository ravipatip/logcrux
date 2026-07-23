from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# SaltStack minion/master log. Default format is "ts [logger:line ][LEVEL ][pid]
# message":
#   2026-06-28 10:15:01,123 [salt.utils.process:1100][INFO    ][1234] Process manager
#   2026-06-28 10:15:02,456 [salt.minion      :2300][WARNING ][1234] Minion unable
#   2026-06-28 10:15:03,789 [salt.crypt       :600 ][ERROR   ][1234] Authentication
# Distinguished by the "[salt.*:line][LEVEL]" bracket pair.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d+)?) "
    r"\[(?P<logger>salt[\w.]*)\s*:\d+\s*\]"
    r"\[(?P<level>\w+)\s*\]"
    r"\[(?P<pid>\d+)\] (?P<message>.*)$"
)


class SaltStackParser(LogParser):
    FORMAT_NAME = "saltstack"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace(",", "."))
        except (ValueError, TypeError, OverflowError):
            ts = None
        level = m["level"]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source=m["logger"],
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": level.lower(), "logger": m["logger"], "pid": m["pid"]},
        )
