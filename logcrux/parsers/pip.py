from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# pip install/resolve output (untimestamped). Recognised by its progress verbs
# and ERROR:/WARNING: diagnostics:
#   Collecting requests
#     Downloading requests-2.31.0-py3-none-any.whl (62 kB)
#   Requirement already satisfied: urllib3 in ./venv/lib/python3.11/site-packages
#   Installing collected packages: requests
#   Successfully installed requests-2.31.0
#   ERROR: Could not find a version that satisfies the requirement foo
#   WARNING: You are using pip version 21.0; however, version 23.0 is available.
_LEVEL_RE = re.compile(r"^(?P<level>ERROR|WARNING|DEPRECATION): (?P<message>.*)$")
_MARKERS = ("Collecting ", "Downloading ", "Requirement already satisfied",
            "Installing collected packages", "Successfully installed",
            "Successfully uninstalled", "Building wheel", "Using cached")
_FAIL_WORDS = ("could not", "no matching distribution", "failed building",
               "error:", "is not a supported wheel")


class PipParser(LogParser):
    FORMAT_NAME = "pip"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(any(mk in ln for mk in _MARKERS) for ln in sample_lines[:30])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line.strip():
            return None
        stripped = line.rstrip()
        lm = _LEVEL_RE.match(stripped.lstrip())
        if lm:
            level = lm["level"]
            severity = Severity.ERROR if level == "ERROR" else Severity.WARNING
            message = lm["message"].strip()
        else:
            severity = Severity.INFO
            message = stripped.strip()
            low = message.lower()
            if any(w in low for w in _FAIL_WORDS):
                severity = Severity.ERROR
        return ParsedEvent(
            timestamp=None,
            severity=severity,
            source="pip",
            message=message,
            raw=line,
            line_number=line_number,
            extra={},
        )
