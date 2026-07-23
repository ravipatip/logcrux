from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Chef Infra client run log. The chef-client formatter emits
# "[ISO8601] LEVEL: message":
#   [2026-06-28T10:15:01+00:00] INFO: Chef Infra Client, version 18.3.0
#   [2026-06-28T10:15:02+00:00] WARN: Cookbook 'apt' is empty
#   [2026-06-28T10:15:03+00:00] ERROR: Running exception handlers
#   [2026-06-28T10:15:04+00:00] FATAL: Stacktrace dumped to ...
# The bracketed ISO timestamp + LEVEL: is shared with other tools, so detection
# additionally requires Chef-specific vocabulary in the sample.
_PATTERN = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?)\] "
    r"(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|FATAL): (?P<message>.*)$"
)
_CHEF_MARKERS = ("chef", "cookbook", "recipe", "resource", "converge",
                 "ohai", "Compiling", "Converging", "Stacktrace", "Infra Client",
                 "run_list", "node[")


class ChefParser(LogParser):
    FORMAT_NAME = "chef"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:20] if _PATTERN.match(ln)]
        if not matched:
            return False
        return any(
            mk.lower() in ln.lower() for ln in matched for mk in _CHEF_MARKERS
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        level = m["level"]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source="chef-client",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"level": level.lower()},
        )
