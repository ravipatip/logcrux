from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# Apache Maven build output — each line is prefixed with a bracketed level:
#   [INFO] Scanning for projects...
#   [INFO] Building my-app 1.0.0
#   [WARNING] Using platform encoding to copy filtered resources
#   [ERROR] Failed to execute goal ... Compilation failure
#   [INFO] BUILD FAILURE
_PATTERN = re.compile(r"^\[(?P<level>INFO|WARNING|ERROR|DEBUG|FATAL)\] (?P<message>.*)$")
# Maven-specific phrases — required so a generic "[INFO] ..." log can't claim it.
_MARKERS = (
    "scanning for projects", "building ", "build success", "build failure",
    "--- maven-", "--- ", "reactor build order", "reactor summary",
    "total time:", "finished at:", "failed to execute goal", "t e s t s",
    "downloading from", "downloaded from",
)


class MavenParser(LogParser):
    FORMAT_NAME = "maven"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        bracketed = 0
        has_marker = False
        for ln in sample_lines[:30]:
            m = _PATTERN.match(ln)
            if m:
                bracketed += 1
                if any(k in m["message"].lower() for k in _MARKERS):
                    has_marker = True
        nonblank = sum(1 for ln in sample_lines[:30] if ln.strip())
        return has_marker and nonblank > 0 and bracketed * 2 >= nonblank

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        level = m["level"]
        message = m["message"].strip()
        severity = level_to_severity(level)
        if level == "INFO" and message.upper().startswith("BUILD FAILURE"):
            severity = Severity.ERROR
        return ParsedEvent(
            timestamp=None,
            severity=severity,
            source="maven",
            message=message,
            raw=line,
            line_number=line_number,
            extra={"level": level.lower()},
        )
