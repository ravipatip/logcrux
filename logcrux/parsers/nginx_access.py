from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.apache_access import _status_severity
from logcrux.parsers.base import LogParser

_PATTERN = re.compile(
    r"(?P<client_ip>\S+) \S+ \S+ "
    r"\[(?P<timestamp>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r"(?P<status_code>\d{3}) (?P<response_bytes>\S+)"
    r'(?: "[^"]*" "[^"]*" (?P<request_time>[\d.]+))?'
)


class NginxAccessParser(LogParser):
    FORMAT_NAME = "nginx-access"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "nginx" in str(path) and "access" in path.name:
            return True
        # Don't claim apache/httpd paths via content detection — the CLF format
        # is shared with Apache and apache_access.py owns those paths.
        if path and ("apache" in str(path) or "httpd" in str(path)):
            return False
        return any(_PATTERN.match(line) for line in sample_lines[:5])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        status = int(m["status_code"])
        try:
            ts = dateparser.parse(m["timestamp"], fuzzy=True)
        except Exception:
            ts = None
        extra: dict[str, object] = {
            "client_ip": m["client_ip"],
            "method": m["method"],
            "path": m["path"],
            "status_code": status,
            "response_bytes": m["response_bytes"],
        }
        if m["request_time"]:
            extra["request_time"] = m["request_time"]
        return ParsedEvent(
            timestamp=ts,
            severity=_status_severity(status),
            source="nginx",
            message=f'{m["method"]} {m["path"]} {status}',
            raw=line,
            line_number=line_number,
            extra=extra,
        )
