from __future__ import annotations

import re
import shlex
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.apache_access import _status_severity
from logcrux.parsers.base import LogParser

# AWS Application/Classic Load Balancer access logs. Space-separated with quoted
# fields; the line begins with a connection type and an ISO-8601 timestamp,
# followed by the load-balancer id:
#   https 2026-06-23T10:23:45.123456Z app/my-alb/0a1b 10.0.0.1:54321 10.0.1.5:8080
#     0.001 0.002 0.003 200 200 412 1234 "GET https://x:443/api HTTP/1.1" "curl/8"
#     ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:...  "Root=1-..." "x.example.com" ...
_TYPES = {"http", "https", "h2", "grpcs", "ws", "wss"}
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def _looks_like_alb(line: str) -> bool:
    parts = line.split(" ", 3)
    if len(parts) < 3:
        return False
    return (
        parts[0] in _TYPES
        and bool(_ISO_RE.match(parts[1]))
        and (parts[2].startswith("app/") or parts[2].startswith("net/") or "/" in parts[2])
    )


class ALBParser(LogParser):
    FORMAT_NAME = "alb"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for line in sample_lines[:10]:
            if line.strip() and _looks_like_alb(line):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line.strip() or not _looks_like_alb(line):
            return None
        try:
            fields = shlex.split(line)
        except ValueError:
            fields = line.split()
        if len(fields) < 13:
            return None
        conn_type, ts_raw, elb, client, target = fields[:5]
        elb_status = fields[8]
        target_status = fields[9]
        request = fields[12] if len(fields) > 12 else ""
        ts: datetime | None
        try:
            ts = dateparser.parse(ts_raw)
        except (ValueError, TypeError, OverflowError):
            ts = None
        # "-" appears when the LB couldn't get a response (e.g. target reset);
        # fall back to INFO rather than inventing an error for an absent code.
        severity = Severity.INFO
        try:
            severity = _status_severity(int(elb_status))
        except ValueError:
            pass
        message = f"{conn_type} {request} -> {elb_status}"
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="alb",
            message=message,
            raw=line,
            line_number=line_number,
            extra={
                "elb": elb,
                "client": client,
                "target": target,
                "elb_status_code": elb_status,
                "target_status_code": target_status,
            },
        )
