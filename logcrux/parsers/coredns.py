from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# CoreDNS logs a bracketed level, optionally preceded by an ISO timestamp:
#   [INFO] plugin/reload: Running configuration MD5 = abc123
#   [ERROR] plugin/errors: 2 example.com. A: read udp 10.0.0.2:53: i/o timeout
#   2026-06-20T10:23:45.123Z [INFO] 10.0.0.5:5353 - 12345 "A IN x. udp 30 false 512" NOERROR
_PATTERN = re.compile(
    r"(?:(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+)?"
    r"\[(?P<level>INFO|WARNING|ERROR|FATAL|DEBUG)\]\s+"
    r"(?P<message>.*)"
)

# A query-log line: "client:port - id "QTYPE QCLASS name proto size do bufsize" RCODE ..."
_QUERY_RE = re.compile(
    r'^(?P<client>\S+) - \d+ "(?P<qtype>\w+) (?P<qclass>\w+) (?P<name>\S+)'
)

_LEVEL_MAP: dict[str, Severity] = {
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "FATAL": Severity.CRITICAL,
}


class CoreDNSParser(LogParser):
    FORMAT_NAME = "coredns"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "coredns" in str(path).lower():
            return True
        hits = 0
        for line in sample_lines[:10]:
            m = _PATTERN.match(line)
            # Require a CoreDNS-shaped body (plugin/... or a DNS query) so we
            # don't grab any generic "[INFO] ..." application line.
            if m and ("plugin/" in m["message"] or _QUERY_RE.match(m["message"])):
                hits += 1
        return hits > 0

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        ts = None
        if m["ts"]:
            try:
                ts = dateparser.parse(m["ts"])
            except (ValueError, TypeError, OverflowError):
                ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"level": m["level"]}
        q = _QUERY_RE.match(message)
        if q:
            extra["client"] = q["client"]
            extra["query_type"] = q["qtype"]
            extra["query_name"] = q["name"]
        return ParsedEvent(
            timestamp=ts,
            severity=_LEVEL_MAP.get(m["level"], Severity.INFO),
            source="coredns",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
