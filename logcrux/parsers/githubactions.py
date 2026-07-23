from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# GitHub Actions runner / step logs — every line is prefixed with an RFC3339
# UTC timestamp carrying 7-digit (100-ns) fractional seconds; workflow commands
# are embedded as "##[...]":
#   2026-06-20T10:15:01.1234567Z Starting: Run build
#   2026-06-20T10:15:02.0000000Z ##[group]Run actions/checkout@v4
#   2026-06-20T10:15:03.0000000Z ##[error]Process completed with exit code 1.
#   2026-06-20T10:15:04.0000000Z ##[warning]Node.js 16 actions are deprecated.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z) (?P<rest>.*)$"
)
_COMMAND = re.compile(r"^##\[(?P<cmd>[a-z]+)\](?P<message>.*)$")


class GitHubActionsParser(LogParser):
    FORMAT_NAME = "githubactions"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = sum(1 for ln in sample_lines[:20] if _PATTERN.match(ln))
        nonblank = sum(1 for ln in sample_lines[:20] if ln.strip())
        # The 7-digit fractional second is the GitHub-specific tell.
        return nonblank > 0 and matched * 2 >= nonblank

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        rest = m["rest"]
        severity = Severity.INFO
        message = rest.strip()
        extra: dict[str, object] = {}
        cmd = _COMMAND.match(rest)
        if cmd:
            command = cmd["cmd"]
            extra["command"] = command
            message = cmd["message"].strip() or command
            if command == "error":
                severity = Severity.ERROR
            elif command == "warning":
                severity = Severity.WARNING
            elif command == "debug":
                severity = Severity.DEBUG
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="github-actions",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
