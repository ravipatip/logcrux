from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Fluent Bit (the standard Kubernetes/cloud log forwarder) default console log:
#   [2026/06/23 10:23:45] [ info] [engine] started (pid=1)
#   [2026/06/23 10:23:45] [error] [output:es:es.0] could not flush records
# Fluentd uses a similar bracketed shape:
#   2026-06-23 10:23:45 +0000 [warn]: #0 buffer flush took longer than ...
_FLUENTBIT_RE = re.compile(
    r"^\[(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\]\s+"
    r"\[\s*(?P<level>trace|debug|info|warn|warning|error)\s*\]\s+"
    r"(?:\[(?P<component>[^\]]+)\]\s+)?(?P<message>.*)$"
)
_FLUENTD_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})\s+"
    r"\[(?P<level>trace|debug|info|warn|warning|error|fatal)\]:\s?(?P<message>.*)$"
)


class FluentBitParser(LogParser):
    FORMAT_NAME = "fluentbit"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for line in sample_lines[:10]:
            if _FLUENTBIT_RE.match(line) or _FLUENTD_RE.match(line):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _FLUENTBIT_RE.match(line)
        component = None
        if m:
            ts = self._ts(m["ts"].replace("/", "-"))
            component = m["component"]
            level, message = m["level"], m["message"]
        else:
            m = _FLUENTD_RE.match(line)
            if not m:
                return None
            ts = self._ts(m["ts"])
            level, message = m["level"], m["message"]
        extra: dict[str, object] = {"level": level}
        if component:
            extra["component"] = component
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source=str(component or "fluentbit"),
            message=message.strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )

    @staticmethod
    def _ts(raw: str) -> datetime | None:
        try:
            return dateparser.parse(raw)
        except (ValueError, TypeError, OverflowError):
            return None
