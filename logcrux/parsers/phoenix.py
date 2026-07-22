from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Elixir / Erlang Logger default console output (Phoenix, OTP releases). Layout
# is "HH:MM:SS.mmm [level] message":
#   10:15:01.123 [info] Running MyAppWeb.Endpoint with cowboy 2.10
#   10:15:02.234 [warning] Sending 500 in 1ms
#   10:15:03.345 [error] GenServer terminating: ** (RuntimeError) boom
# The "HH:MM:SS.mmm [level]" time-only + lowercase-level shape is the signature.
_PATTERN = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2}\.\d{3}) "
    r"\[(?P<level>debug|info|notice|warn|warning|error|critical|alert|emergency)\]"
    r"(?:\s+(?P<message>.*))?$"
)


class PhoenixParser(LogParser):
    FORMAT_NAME = "phoenix"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        nonblank = [ln for ln in sample_lines[:25] if ln.strip()]
        if not nonblank:
            return False
        matched = sum(bool(_PATTERN.match(ln)) for ln in nonblank)
        return matched * 2 >= len(nonblank) and matched >= 1

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        return ParsedEvent(
            timestamp=None,
            severity=level_to_severity(m["level"]),
            source="phoenix",
            message=(m["message"] or "").strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"]},
        )
