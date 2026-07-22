from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Jenkins system log (java.util.logging default), the controller's jenkins.log:
#   2026-06-23 10:23:45.123+0000 [id=42]   INFO    hudson.WebAppMain#init: ...
#   2026-06-23 10:23:45.123+0000 [id=88]   SEVERE  hudson.model.Run: build failed
# Java level names: FINEST/FINER/FINE=debug, CONFIG/INFO=info, WARNING=warn,
# SEVERE=error.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{4})\s+"
    r"\[id=(?P<id>\d+)\]\s+"
    r"(?P<level>FINEST|FINER|FINE|CONFIG|INFO|WARNING|SEVERE)\s+"
    r"(?P<logger>\S+?):?\s+(?P<message>.*)$"
)
_LEVEL_MAP = {
    "FINEST": Severity.DEBUG,
    "FINER": Severity.DEBUG,
    "FINE": Severity.DEBUG,
    "CONFIG": Severity.INFO,
    "INFO": Severity.INFO,
    "WARNING": Severity.WARNING,
    "SEVERE": Severity.ERROR,
}


class JenkinsParser(LogParser):
    FORMAT_NAME = "jenkins"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "jenkins" in str(path).lower():
            return True
        for line in sample_lines[:10]:
            if _PATTERN.match(line):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        ts: datetime | None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="jenkins",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"], "logger": m["logger"], "thread_id": m["id"]},
        )
