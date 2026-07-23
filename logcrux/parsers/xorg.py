from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Xorg server log (/var/log/Xorg.0.log). Each line is "[ uptime] (M) message",
# where the marker letter pair encodes the message class:
#   [    12.345] (II) Module already built-in
#   [    12.346] (WW) warning, (EE) error, (NI) not implemented, (--) probed
#   [    12.347] (EE) Failed to load module "nvidia"
# The "[float] (MM)" shape is the distinctive signature.
_PATTERN = re.compile(
    r"^\[\s*(?P<uptime>\d+\.\d+)\] "
    r"\((?P<marker>II|WW|EE|NI|--|\+\+|\*\*)\) "
    r"(?P<message>.*)$"
)
_MARKER_SEVERITY = {
    "EE": Severity.ERROR,
    "WW": Severity.WARNING,
    "NI": Severity.WARNING,
    "II": Severity.INFO,
    "--": Severity.INFO,
    "++": Severity.INFO,
    "**": Severity.DEBUG,
}


class XorgParser(LogParser):
    FORMAT_NAME = "xorg"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        return ParsedEvent(
            timestamp=None,
            severity=_MARKER_SEVERITY.get(m["marker"], Severity.INFO),
            source="xorg",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"marker": m["marker"], "uptime": m["uptime"]},
        )
