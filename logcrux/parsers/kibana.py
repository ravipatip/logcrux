from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Kibana legacy (pre-7.4) server log. Layout is
# "log   [HH:MM:SS.mmm] [level][tag][tag] message":
#   log   [10:15:01.123] [info][listening] Server running at http://0.0.0.0:5601
#   log   [10:15:02.234] [warning][process] memwatch leak detected
#   log   [10:15:03.345] [error][elasticsearch][admin] Request error, retrying
# The leading "log   [time] [level]" shape is the distinctive Kibana signature.
_PATTERN = re.compile(
    r"^log\s+\[(?P<ts>\d{2}:\d{2}:\d{2}\.\d{3})\] "
    r"\[(?P<level>\w+)\]"
    r"(?P<tags>(?:\[[^\]]*\])*)"
    r"\s*(?P<message>.*)$"
)


class KibanaParser(LogParser):
    FORMAT_NAME = "kibana"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:25])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        extra: dict[str, object] = {"level": m["level"].lower()}
        tags = re.findall(r"\[([^\]]*)\]", m["tags"])
        if tags:
            extra["tags"] = ",".join(tags)
        return ParsedEvent(
            timestamp=None,
            severity=level_to_severity(m["level"]),
            source="kibana",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
