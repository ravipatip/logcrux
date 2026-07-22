from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Zabbix server / agent / proxy log. Each line is "PID:YYYYMMDD:HHMMSS.mmm
# message":
#   12345:20260628:101501.123 Starting Zabbix Server. Zabbix 6.4.0
#   12345:20260628:101502.456 [Z3005] query failed: ... cannot connect to DB
#   12345:20260628:101503.789 housekeeper [deleted 0 hist] in 0.01 sec
# The "PID:date:time.millis" prefix is the distinctive signature.
_PATTERN = re.compile(
    r"^(?P<pid>\d+):(?P<date>\d{8}):(?P<time>\d{6}\.\d{3}) (?P<message>.*)$"
)
_ERROR_MARKERS = ("cannot", "failed", "error", "unable", "no data", "down",
                  "is not running", "crashed", "fatal", "refused", "timed out",
                  "lost connection", "[z3005]", "[z3001]")
_WARN_MARKERS = ("warning", "slow query", "lagging", "lag", "busy",
                 "queue", "more than", "exceeded", "retrying", "delayed")


def _severity(message: str) -> Severity:
    low = message.lower()
    if any(m in low for m in _ERROR_MARKERS):
        return Severity.ERROR
    if any(m in low for m in _WARN_MARKERS):
        return Severity.WARNING
    return Severity.INFO


class ZabbixParser(LogParser):
    FORMAT_NAME = "zabbix"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        ts = None
        try:
            d = m["date"]
            t = m["time"]
            ts = datetime(
                int(d[0:4]), int(d[4:6]), int(d[6:8]),
                int(t[0:2]), int(t[2:4]), int(t[4:6]),
                int(t[7:10]) * 1000,
            )
        except (ValueError, IndexError):
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(m["message"]),
            source="zabbix",
            message=m["message"].strip(),
            raw=line,
            line_number=line_number,
            extra={"pid": m["pid"]},
        )
