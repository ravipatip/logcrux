from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# cloud-init writes /var/log/cloud-init.log on first boot of nearly every cloud
# VM (Amazon Linux 2 / 2023, Ubuntu, RHEL, ...). Format:
#   2026-06-23 10:23:45,123 - util.py[WARNING]: Failed to ... [3/5]
#   2026-06-23 10:23:45,123 - stages.py[DEBUG]: Running module final-message
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+-\s+"
    r"(?P<module>[\w.\-]+)\[(?P<level>[A-Z]+)\]:\s?(?P<message>.*)$"
)


class CloudInitParser(LogParser):
    FORMAT_NAME = "cloudinit"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "cloud-init" in str(path).lower():
            return True
        for line in sample_lines[:10]:
            if _PATTERN.match(line):
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
            source="cloud-init",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"module": m["module"], "level": m["level"]},
        )
