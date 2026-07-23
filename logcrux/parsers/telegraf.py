from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# InfluxData Telegraf metrics-agent log. Layout is "ts L! [component] message":
#   2026-06-28T10:15:01Z I! Loaded inputs: cpu mem disk net
#   2026-06-28T10:15:02Z W! [inputs.docker] Error gathering: connection refused
#   2026-06-28T10:15:03Z E! [agent] Error writing to outputs.influxdb: timeout
# The "ts <L>! [component]" shape mirrors the CloudWatch agent's "I!" marker, so
# detection is gated on a Telegraf [agent]/[inputs.…]/[outputs.…] component tag.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<lvl>[DIWE])! "
    r"(?:\[(?P<component>[^\]]+)\] )?"
    r"(?P<message>.*)$"
)
_LEVEL = {"D": "debug", "I": "info", "W": "warn", "E": "error"}
_COMPONENT_MARKERS = ("agent", "inputs.", "outputs.", "processors.",
                      "aggregators.", "telegraf")


class TelegrafParser(LogParser):
    FORMAT_NAME = "telegraf"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        # The CloudWatch agent shares the "ts L! [component]" layout *and* uses
        # [outputs.cloudwatchlogs]/[logagent] components — leave those files to
        # the cloudwatch parser (which sits after telegraf in the registry).
        if any("cloudwatch" in ln.lower() for ln in sample_lines[:25]):
            return False
        for ln in sample_lines[:25]:
            m = _PATTERN.match(ln)
            if m and m["component"] and any(
                m["component"].startswith(mk) or m["component"] == "agent"
                for mk in _COMPONENT_MARKERS
            ):
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
        extra: dict[str, object] = {"level": _LEVEL[m["lvl"]]}
        if m["component"]:
            extra["component"] = m["component"]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(_LEVEL[m["lvl"]]),
            source="telegraf",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
