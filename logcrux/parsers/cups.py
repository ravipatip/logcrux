from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# CUPS error_log: a single level letter, a bracketed CLF-style timestamp, msg.
#   E [20/Jun/2026:10:23:45 +0000] Unable to open listen socket for address ...
#   W [20/Jun/2026:10:23:45 +0000] CreateProfile failed: org.freedesktop...
#   I [20/Jun/2026:10:23:45 +0000] Listening to 127.0.0.1:631 (IPv4)
# Level letters: X=alert A=alert C=crit E=error W=warn N=notice I=info
#                D=debug d=debug2
_PATTERN = re.compile(
    r"(?P<level>[XACEWNIDd]) "
    r"\[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "
    r"(?P<message>.*)"
)

_LEVEL_MAP: dict[str, Severity] = {
    "X": Severity.CRITICAL,
    "A": Severity.CRITICAL,
    "C": Severity.CRITICAL,
    "E": Severity.ERROR,
    "W": Severity.WARNING,
    "N": Severity.INFO,
    "I": Severity.INFO,
    "D": Severity.DEBUG,
    "d": Severity.DEBUG,
}


class CupsParser(LogParser):
    FORMAT_NAME = "cups"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "cups" in str(path).lower():
            return True
        return any(_PATTERN.match(line) for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        # CLF timestamp: 20/Jun/2026:10:23:45 +0000 -> ISO for dateutil.
        ts_raw = m["ts"]
        try:
            d, rest = ts_raw.split(":", 1)
            day, mon, year = d.split("/")
            ts = dateparser.parse(f"{day} {mon} {year} {rest}")
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="cups",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"]},
        )
