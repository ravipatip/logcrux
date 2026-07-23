from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# LXC container runtime logs (lxc-start / liblxc). Layout is
# "lxc <name> YYYYMMDDHHMMSS.mmm LEVEL <component> - file.c: func: line - msg":
#   lxc web 20260628101501.234 INFO     conf - conf.c: lxc_setup: 4321 - container setup
#   lxc web 20260628101502.345 WARN     start - start.c: print_top_failing: 100 - slow
#   lxc web 20260628101503.456 ERROR    conf - conf.c: run_buffer: 322 - hook failed
# The "lxc <name> <14-digit-ts>.mmm LEVEL <comp> -" shape is the signature.
_PATTERN = re.compile(
    r"^lxc (?P<name>\S+) "
    r"(?P<ts>\d{14}\.\d{3}) "
    r"(?P<level>TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRIT|FATAL|ALERT)\s+"
    r"(?P<comp>\S+) - "
    r"(?P<src>[^-]+?) - "
    r"(?P<message>.*)$"
)


class LxcParser(LogParser):
    FORMAT_NAME = "lxc"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:25])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = datetime.strptime(m["ts"], "%Y%m%d%H%M%S.%f")
        except ValueError:
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="lxc",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={
                "container": m["name"],
                "level": m["level"].lower(),
                "component": m["comp"],
                "src": m["src"].strip(),
            },
        )
