from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.apache_access import _status_severity
from logcrux.parsers.base import LogParser, level_to_severity

# Envoy powers Istio sidecars / ingress and emits two distinct log shapes.
#
# 1. Access log (default format), one HTTP request per line:
#    [2026-06-23T10:23:45.123Z] "GET /api HTTP/1.1" 200 - 0 1234 5 4
#      "-" "curl" "req-id" "host" "10.0.0.1:8080"
#
# 2. Application/admin log:
#    [2026-06-23 10:23:45.123][14][info][config] [source/file.cc:123] message
_ACCESS_RE = re.compile(
    r'^\[(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>HTTP/\d(?:\.\d)?)"\s+'
    r"(?P<status>\d{3})\s+(?P<flags>\S+)\s"
)
_APP_RE = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\]"
    r"\[(?P<thread>\d+)\]"
    r"\[(?P<level>trace|debug|info|warning|warn|error|critical)\]"
    r"\[(?P<component>[^\]]+)\]\s+(?P<message>.*)$"
)


class EnvoyParser(LogParser):
    FORMAT_NAME = "envoy"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and ("envoy" in str(path).lower() or "istio" in str(path).lower()):
            return True
        for line in sample_lines[:10]:
            if _ACCESS_RE.match(line) or _APP_RE.match(line):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        app = _APP_RE.match(line)
        if app:
            ts = self._ts(app["ts"])
            return ParsedEvent(
                timestamp=ts,
                severity=level_to_severity(app["level"]),
                source="envoy",
                message=app["message"].strip(),
                raw=line,
                line_number=line_number,
                extra={"level": app["level"], "component": app["component"]},
            )
        access = _ACCESS_RE.match(line)
        if access:
            status = int(access["status"])
            # Same status→severity convention as the web-access parsers so an
            # Envoy access log isn't noisier than an nginx/apache one.
            severity = _status_severity(status)
            message = (
                f'{access["method"]} {access["path"]} {access["proto"]} '
                f'-> {access["status"]}'
            )
            return ParsedEvent(
                timestamp=self._ts(access["ts"]),
                severity=severity,
                source="envoy",
                message=message,
                raw=line,
                line_number=line_number,
                extra={
                    "method": access["method"],
                    "status": access["status"],
                    "response_flags": access["flags"],
                },
            )
        return None

    @staticmethod
    def _ts(raw: str) -> datetime | None:
        try:
            return dateparser.parse(raw)
        except (ValueError, TypeError, OverflowError):
            return None
