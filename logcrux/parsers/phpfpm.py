from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# PHP-FPM (FastCGI Process Manager) log format:
#   [20-Jun-2024 10:23:45] NOTICE: fpm is running, pid 1234
#   [20-Jun-2024 10:23:45] WARNING: [pool www] server reached pm.max_children (5)
#   [20-Jun-2024 10:23:45] ERROR: failed to ptrace(PEEKDATA) pid 4242
_PATTERN = re.compile(
    r"\[(?P<ts>\d{1,2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2})\] "
    r"(?P<level>DEBUG|NOTICE|WARNING|ERROR|ALERT): "
    r"(?P<message>.*)"
)

_POOL_RE = re.compile(r"^\[pool (?P<pool>[^\]]+)\]\s*")

_LEVEL_MAP: dict[str, Severity] = {
    "DEBUG": Severity.DEBUG,
    "NOTICE": Severity.INFO,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "ALERT": Severity.CRITICAL,
}


class PhpFpmParser(LogParser):
    FORMAT_NAME = "php-fpm"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        name = path.name.lower() if path else ""
        if "php-fpm" in name or "php_fpm" in name or "fpm" in name:
            return True
        return any(_PATTERN.match(line) for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace("-", " ", 2))
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {}
        pool = _POOL_RE.match(message)
        if pool:
            extra["pool"] = pool["pool"]
            message = message[pool.end():].strip()
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="php-fpm",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
