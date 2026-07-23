from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Datadog Agent log (agent.log / trace-agent.log / process-agent.log). A
# pipe-delimited layout with a timezone-stamped time, the agent component, the
# level and the source location:
#   2026-06-20 10:15:01 UTC | CORE | INFO | (pkg/collector/runner.go:340 in work) | Running check
#   2026-06-20 10:15:02 UTC | CORE | WARN | (pkg/forwarder/transaction.go:392) | Failed to post
#   2026-06-20 10:15:03 UTC | APM  | ERROR | (...) | Unable to start
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<tz>\w+) \| "
    r"(?P<agent>[A-Z][A-Z ]*?) \| "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL) \| "
    r"\((?P<loc>[^)]*)\) \| (?P<message>.*)$"
)


class DatadogParser(LogParser):
    FORMAT_NAME = "datadog"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _PATTERN.match(ln):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f"{m['ts']} {m['tz']}")
        except (ValueError, TypeError, OverflowError):
            try:
                ts = dateparser.parse(m["ts"])
            except (ValueError, TypeError, OverflowError):
                ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="datadog-agent",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={
                "level": m["level"].lower(),
                "agent": m["agent"].strip(),
                "location": m["loc"],
            },
        )
