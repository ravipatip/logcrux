from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# WildFly / JBoss EAP application-server log (server.log). Layout is
# "HH:MM:SS,mmm LEVEL [logger] (thread) CODE: message":
#   10:15:01,123 INFO  [org.jboss.modules] (main) JBoss Modules version 2.0
#   10:15:02,234 WARN  [org.jboss.as.txn] (Controller Boot) WFLYTX0013: recovery
#   10:15:03,345 ERROR [org.jboss.as.controller] (Controller Boot) WFLYCTL0013: failed
# The "time-only ts LEVEL [org.jboss/org.wildfly logger] (thread) WFLY/JBAS code"
# shape is the distinctive signature.
_PATTERN = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2},\d{3}) "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+"
    r"\[(?P<logger>[^\]]+)\] "
    r"\((?P<thread>[^)]*)\) "
    r"(?P<message>.*)$"
)
_MARKERS = ("org.jboss", "org.wildfly", "WFLY", "JBAS", "jboss", "wildfly")


class WildflyParser(LogParser):
    FORMAT_NAME = "wildfly"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:25] if _PATTERN.match(ln)]
        if not matched:
            return False
        return any(mk in ln for ln in matched for mk in _MARKERS)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        # Time-only timestamp; no date in the WildFly default pattern.
        try:
            ts = dateparser.parse(m["time"].replace(",", "."))
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {
            "level": m["level"].lower(),
            "logger": m["logger"],
            "thread": m["thread"],
        }
        code_m = re.match(r"([A-Z]{3,}\d{4,}):", message)
        if code_m:
            extra["code"] = code_m.group(1)
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="wildfly",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
