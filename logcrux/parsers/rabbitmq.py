from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# RabbitMQ (modern, RabbitMQ 3.7+) log format:
#   2024-06-20 10:23:45.123 [info] <0.612.0> accepting AMQP connection <0.612.0> \
#       (10.0.0.5:5672 -> 10.0.0.1:5672)
#   2024-06-20 10:23:45.456 [error] <0.700.0> Error on AMQP connection: closed
# The Erlang process id "<0.NNN.0>" reliably distinguishes RabbitMQ from other
# "YYYY-MM-DD HH:MM:SS.mmm [level]" loggers.
_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"\[(?P<level>\w+)\] "
    r"(?P<pid><\d+\.\d+\.\d+>)?\s*"
    r"(?P<message>.*)"
)

_LEVEL_MAP: dict[str, Severity] = {
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "notice": Severity.INFO,
    "warning": Severity.WARNING,
    "warn": Severity.WARNING,
    "error": Severity.ERROR,
    "critical": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "emergency": Severity.CRITICAL,
}


class RabbitMQParser(LogParser):
    FORMAT_NAME = "rabbitmq"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "rabbit" in path.name.lower():
            return True
        matched = 0
        for line in sample_lines[:10]:
            m = _PATTERN.match(line)
            # Require the Erlang pid on at least one line to avoid stealing
            # other "date [level]" formats.
            if m and m["pid"]:
                matched += 1
        return matched > 0

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        extra: dict[str, object] = {}
        if m["pid"]:
            extra["erlang_pid"] = m["pid"]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"].lower(), Severity.INFO),
            source="rabbitmq",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
