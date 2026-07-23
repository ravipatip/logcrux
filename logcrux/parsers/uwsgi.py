from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# uWSGI request log:
#   [pid: 1234|app: 0|req: 1/1] 1.2.3.4 () {44 vars in 1024 bytes}
#   [Thu Jun 20 10:15:01 2026] GET /api => generated 1234 bytes in 5 msecs
#   (HTTP/1.1 200) 2 headers in 80 bytes (1 switches on core 0)
_PATTERN = re.compile(
    r"^\[pid: (?P<pid>\d+)\|app: (?P<app>\d+)\|req: (?P<req>[\d/]+)\] "
    r"(?P<client>\S+) \([^)]*\) \{[^}]*\} "
    r"\[(?P<ts>[^\]]+)\] (?P<method>\w+) (?P<path>\S+) => "
    r"generated (?P<bytes>\d+) bytes in (?P<msecs>\d+) msecs "
    r"\(HTTP/[\d.]+ (?P<status>\d{3})\)"
)


class UwsgiParser(LogParser):
    FORMAT_NAME = "uwsgi"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if ln.startswith("[pid: ") and "|req: " in ln:
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        status = int(m["status"])
        if status >= 500:
            severity = Severity.ERROR
        elif status >= 400:
            severity = Severity.WARNING
        else:
            severity = Severity.INFO
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="uwsgi",
            message=f'{m["method"]} {m["path"]} -> {status} ({m["msecs"]}ms)',
            raw=line,
            line_number=line_number,
            extra={
                "client": m["client"],
                "method": m["method"],
                "path": m["path"],
                "status": status,
                "duration_ms": int(m["msecs"]),
            },
        )
