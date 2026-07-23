from __future__ import annotations

import re
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# Uvicorn / Gunicorn-uvicorn ASGI server default console output:
#   INFO:     Started server process [12345]
#   INFO:     127.0.0.1:54321 - "GET /api HTTP/1.1" 200 OK
#   WARNING:  Invalid HTTP request received.
#   ERROR:    Exception in ASGI application
# Shape: "LEVEL:" left-padded to a fixed column (>=1 space), then the message.
_PATTERN = re.compile(
    r"^(?P<level>TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL):\s{2,}(?P<message>.*)$"
)
# The access-log message embeds an HTTP request + status code.
_ACCESS_RE = re.compile(
    r'(?P<client>\S+) - "(?P<method>\w+) (?P<path>[^"]*) HTTP/[\d.]+" (?P<status>\d{3})'
)


class UvicornParser(LogParser):
    FORMAT_NAME = "uvicorn"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = sum(1 for ln in sample_lines[:20] if _PATTERN.match(ln))
        nonblank = sum(1 for ln in sample_lines[:20] if ln.strip())
        return nonblank > 0 and matched * 2 >= nonblank

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        level = m["level"]
        message = m["message"].strip()
        severity = level_to_severity(level)
        extra: dict[str, object] = {"level": level.lower()}
        access = _ACCESS_RE.search(message)
        if access:
            status = int(access["status"])
            extra.update(
                {
                    "client": access["client"],
                    "method": access["method"],
                    "path": access["path"],
                    "status": status,
                }
            )
            # An HTTP 5xx is the server's own fault even on an INFO access line.
            if status >= 500:
                severity = Severity.ERROR
            elif status >= 400 and severity == Severity.INFO:
                severity = Severity.WARNING
        return ParsedEvent(
            timestamp=None,
            severity=severity,
            source="uvicorn",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
