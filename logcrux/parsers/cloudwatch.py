from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Amazon CloudWatch agent / amazon-cloudwatch-agent.log (ubiquitous on EC2,
# AL2 and AL2023). It uses Go-style single-letter levels with a "!" suffix:
#   2026-06-23T10:23:45Z I! Starting AmazonCloudWatchAgent
#   2026/06/23 10:23:45 E! [outputs.cloudwatchlogs] Aborted batch
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<level>[DIWE])!\s?(?P<message>.*)$"
)
_LEVEL_MAP = {"D": Severity.DEBUG, "I": Severity.INFO, "W": Severity.WARNING, "E": Severity.ERROR}


class CloudWatchParser(LogParser):
    FORMAT_NAME = "cloudwatch"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "cloudwatch" in str(path).lower():
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
            ts = dateparser.parse(m["ts"].replace("/", "-", 2))
        except (ValueError, TypeError, OverflowError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="cloudwatch-agent",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": m["level"]},
        )
