from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Unbound DNS resolver native log:
#   [1718877301] unbound[12345:0] info: start of service (unbound 1.17.0).
#   [1718877302] unbound[12345:0] error: bind: address already in use
#   [1718877303] unbound[12345:0] notice: remote control failed
_PATTERN = re.compile(
    r"^\[(?P<epoch>\d+)\] unbound\[(?P<pid>\d+):(?P<thread>\d+)\] "
    r"(?P<level>\w+): (?P<message>.*)$"
)


class UnboundParser(LogParser):
    FORMAT_NAME = "unbound"

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
            ts: datetime | None = datetime.fromtimestamp(
                int(m["epoch"]), tz=timezone.utc
            )
        except (ValueError, OSError, OverflowError):
            ts = None
        level = m["level"].lower()
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source="unbound",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": level, "pid": m["pid"]},
        )
