from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Redis 4+ format: pid:role DD Mon YYYY HH:MM:SS.mmm [.*#-] message
# Role: M=master, S=slave/replica, C=child, X=sentinel
_NEW_PATTERN = re.compile(
    r"(?P<pid>\d+):(?P<role>[MSCX]) "
    r"(?P<ts>\d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(?P<symbol>[.*\-#]) "
    r"(?P<message>.*)"
)

# Redis 2.x/3.x format: [pid] DD Mon HH:MM:SS.mmm [.*#-] message
_OLD_PATTERN = re.compile(
    r"\[(?P<pid>\d+)\] "
    r"(?P<ts>\d{2} \w{3} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(?P<symbol>[.*\-#]) "
    r"(?P<message>.*)"
)

_CURRENT_YEAR = __import__("datetime").datetime.now().year

# Symbol → severity mapping
# '.' = debug, '-' = verbose, '*' = notice/info, '#' = warning/alert
_SYMBOL_SEVERITY: dict[str, Severity] = {
    ".": Severity.DEBUG,
    "-": Severity.INFO,
    "*": Severity.INFO,
    "#": Severity.WARNING,
}

# Patterns that elevate to ERROR despite '#' being warning
_ERROR_KEYWORDS = frozenset([
    "oom", "out of memory", "crashed", "panic", "corruption",
    "failed", "can't save", "fork", "rdb", "aof error",
])

_DETECT = re.compile(
    r"(?:\d+:[MSCX] \d{2} \w{3} \d{4})|(?:\[\d+\] \d{2} \w{3} \d{2}:\d{2})"
)


def _redis_severity(symbol: str, message: str) -> Severity:
    base = _SYMBOL_SEVERITY.get(symbol, Severity.INFO)
    if base == Severity.WARNING:
        low = message.lower()
        if any(kw in low for kw in _ERROR_KEYWORDS):
            return Severity.ERROR
    return base


class RedisParser(LogParser):
    FORMAT_NAME = "redis"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            p = str(path).lower()
            if "redis" in p:
                return True
        return any(_DETECT.match(line) for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _NEW_PATTERN.match(line)
        if m:
            return self._make(m, new_format=True, line=line, line_number=line_number)
        m = _OLD_PATTERN.match(line)
        if m:
            return self._make(m, new_format=False, line=line, line_number=line_number)
        return None

    def _make(
        self, m: re.Match[str], new_format: bool, line: str, line_number: int
    ) -> ParsedEvent:
        ts_str = m["ts"]
        if not new_format:
            # Old format has no year — inject it between month and time
            # (e.g. "14 Nov 07:01:22.119" -> "14 Nov 2026 07:01:22.119").
            day, month, clock = ts_str.split()
            ts_str = f"{day} {month} {_CURRENT_YEAR} {clock}"
        try:
            ts = dateparser.parse(ts_str, fuzzy=True)
        except Exception:
            ts = None
        symbol = m["symbol"]
        message = m["message"].strip()
        role_map = {"M": "master", "S": "replica", "C": "child", "X": "sentinel"}
        extra: dict[str, object] = {
            "pid": m["pid"],
            "symbol": symbol,
        }
        if new_format:
            extra["role"] = role_map.get(m["role"], m["role"])
        return ParsedEvent(
            timestamp=ts,
            severity=_redis_severity(symbol, message),
            source="redis",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
