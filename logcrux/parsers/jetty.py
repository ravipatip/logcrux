from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Eclipse Jetty server log (StdErrLog). Layout is
# "ts:LEVEL:logger:thread: message":
#   2026-06-28 10:15:01.123:INFO:oejs.Server:main: jetty-11.0.15
#   2026-06-28 10:15:02.234:WARN:oejsh.ContextHandler:main: unavailable
#   2026-06-28 10:15:03.345:WARN:oejx.XmlConfiguration:main: FAILED
# The "ts:LEVEL:oej*.Logger:thread:" colon-delimited shape is the signature.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}):"
    r"(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|IGNORED|FATAL):"
    r"(?P<logger>[^:]*):"
    r"(?P<thread>[^:]*): "
    r"(?P<message>.*)$"
)
_MARKERS = ("oej", "org.eclipse.jetty", "jetty", "Jetty")


class JettyParser(LogParser):
    FORMAT_NAME = "jetty"

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
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="jetty",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={
                "level": m["level"].lower(),
                "logger": m["logger"],
                "thread": m["thread"],
            },
        )
