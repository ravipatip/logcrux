from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# npm / yarn CLI log output. Each diagnostic line is "npm <level> ...":
#   npm WARN deprecated har-validator@5.1.5: this library is no longer supported
#   npm notice created a lockfile as package-lock.json
#   npm ERR! code ELIFECYCLE
#   npm error code ENOENT       (npm v9+ lowercases the level)
_PATTERN = re.compile(
    r"^npm (?P<level>ERR!|error|WARN|warn|notice|info|http|verbose|timing|sill|silly) "
    r"(?P<message>.*)$"
)
_LEVEL_MAP = {
    "err!": Severity.ERROR,
    "error": Severity.ERROR,
    "warn": Severity.WARNING,
    "notice": Severity.INFO,
    "info": Severity.INFO,
    "http": Severity.DEBUG,
    "verbose": Severity.DEBUG,
    "timing": Severity.DEBUG,
    "sill": Severity.DEBUG,
    "silly": Severity.DEBUG,
}


class NpmParser(LogParser):
    FORMAT_NAME = "npm"

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
        level = m["level"].lower()
        return ParsedEvent(
            timestamp=None,
            severity=_LEVEL_MAP.get(level, Severity.INFO),
            source="npm",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": level},
        )
