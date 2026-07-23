from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Mosquitto MQTT broker log — epoch-second prefix then a free-text message:
#   1718877301: mosquitto version 2.0.15 starting
#   1718877302: New connection from 1.2.3.4:5555 on port 1883.
#   1718877303: Socket error on client mqtt-1, disconnecting.
#   1718877304: Error: Unable to open log file.
_PATTERN = re.compile(r"^(?P<epoch>\d{10}): (?P<message>.+)$")
# Recognisable mosquitto phrases — required so a bare "epoch: text" line from
# another tool can't claim the format.
_MARKERS = (
    "mosquitto version", "new connection", "new client", "client ",
    "socket error", "opening ipv", "opening unix", "config loaded",
    "sending ", "received ", "saving in-memory", "disconnect",
)


class MosquittoParser(LogParser):
    FORMAT_NAME = "mosquitto"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "mosquitto" in str(path).lower():
            return True
        matched = 0
        for ln in sample_lines[:20]:
            m = _PATTERN.match(ln)
            if m and any(k in m["message"].lower() for k in _MARKERS):
                matched += 1
        return matched >= 2

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts: datetime | None = datetime.fromtimestamp(
                int(m["epoch"]), tz=timezone.utc
            )
        except (ValueError, OSError, OverflowError):
            ts = None
        message = m["message"].strip()
        low = message.lower()
        if low.startswith("error") or "unable to" in low or "socket error" in low:
            severity = Severity.ERROR
        elif "disconnect" in low or "refused" in low or "denied" in low:
            severity = Severity.WARNING
        else:
            severity = Severity.INFO
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="mosquitto",
            message=message,
            raw=line,
            line_number=line_number,
            extra={},
        )
