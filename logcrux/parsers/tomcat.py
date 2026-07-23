from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Apache Tomcat (java.util.logging / JULI) catalina.out format:
#   20-Jun-2024 10:23:45.123 INFO [main] org.apache.catalina.startup.Catalina.start \
#       Server startup in [1234] milliseconds
#   20-Jun-2024 10:23:45.456 SEVERE [http-nio-8080-exec-1] o.a.c.c.C.[.[.[/].invoke \
#       Servlet.service() for servlet threw exception
_PATTERN = re.compile(
    r"(?P<ts>\d{1,2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(?P<level>SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST) "
    r"\[(?P<thread>[^\]]+)\] "
    r"(?P<logger>\S+) "
    r"(?P<message>.*)"
)

# JULI levels → logcrux severities. SEVERE is Tomcat's highest (error/fatal).
_LEVEL_MAP: dict[str, Severity] = {
    "SEVERE": Severity.ERROR,
    "WARNING": Severity.WARNING,
    "INFO": Severity.INFO,
    "CONFIG": Severity.INFO,
    "FINE": Severity.DEBUG,
    "FINER": Severity.DEBUG,
    "FINEST": Severity.DEBUG,
}


class TomcatParser(LogParser):
    FORMAT_NAME = "tomcat"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        name = path.name.lower() if path else ""
        if "catalina" in name or "tomcat" in name:
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
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="tomcat",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"thread": m["thread"], "logger": m["logger"]},
        )
