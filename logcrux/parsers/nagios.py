from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Nagios / Icinga / Naemon core log (nagios.log):
#   [1718877301] SERVICE ALERT: web01;HTTP;CRITICAL;HARD;1;HTTP CRITICAL - 500
#   [1718877302] HOST ALERT: db01;DOWN;HARD;1;CRITICAL - host unreachable
#   [1718877303] SERVICE NOTIFICATION: admin;web01;HTTP;CRITICAL;notify;...
#   [1718877304] Nagios 4.4.6 starting... (PID=1234)
_PATTERN = re.compile(r"^\[(?P<epoch>\d+)\] (?P<rest>.+)$")
# State token carried in ALERT/NOTIFICATION records.
_STATE_SEVERITY = {
    "OK": Severity.INFO,
    "UP": Severity.INFO,
    "WARNING": Severity.WARNING,
    "UNKNOWN": Severity.WARNING,
    "CRITICAL": Severity.ERROR,
    "DOWN": Severity.ERROR,
    "UNREACHABLE": Severity.ERROR,
}


class NagiosParser(LogParser):
    FORMAT_NAME = "nagios"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        markers = (
            "SERVICE ALERT:", "HOST ALERT:", "SERVICE NOTIFICATION:",
            "HOST NOTIFICATION:", "CURRENT SERVICE STATE:", "EXTERNAL COMMAND:",
            "LOG ROTATION:", "SERVICE FLAPPING ALERT:",
        )
        count = 0
        for ln in sample_lines[:20]:
            m = _PATTERN.match(ln)
            if m and any(mk in m["rest"] for mk in markers):
                count += 1
        return count >= 1

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
        rest = m["rest"].strip()
        severity = Severity.INFO
        record_type = rest.split(":", 1)[0] if ":" in rest else rest
        # ALERT/NOTIFICATION records carry ;STATE; — pull it for severity.
        if ": " in rest:
            fields = rest.split(": ", 1)[1].split(";")
            for token in fields:
                up = token.strip().upper()
                if up in _STATE_SEVERITY:
                    severity = _STATE_SEVERITY[up]
                    break
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="nagios",
            message=rest,
            raw=line,
            line_number=line_number,
            extra={"record_type": record_type},
        )
