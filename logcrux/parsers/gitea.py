from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Gitea / Forgejo self-hosted Git server log. Layout is
# "YYYY/MM/DD HH:MM:SS path.go:line:func() [L] message":
#   2026/06/28 10:15:01 cmd/web.go:223:runWeb() [I] Starting Gitea on PID: 1234
#   2026/06/28 10:15:02 routers/common/middleware.go:70:1() [W] Slow request 1.2s
#   2026/06/28 10:15:03 services/repository/repo.go:90:Create() [E] Unable to create repo
# The "src.go:line:func() [L]" shape distinguishes Gitea from Go's stdlib log,
# so this parser is checked first.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<src>\S+\.go:\d+:\w+\(\)) "
    r"\[(?P<level>[TDIWEFC])\] "
    r"(?P<message>.*)$"
)


class GiteaParser(LogParser):
    FORMAT_NAME = "gitea"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:25])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace("/", "-"))
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="gitea",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"src": m["src"], "level": m["level"]},
        )
