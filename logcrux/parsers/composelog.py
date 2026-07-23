from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser
from logcrux.parsers.generic import _extract_severity

# ``docker compose logs`` / ``docker-compose up`` multiplexes every service's
# stdout behind a ``<service> | `` prefix:
#   web-1      | 10.0.0.1 - - [23/Jun/2026:10:23:45] "GET / HTTP/1.1" 200 12
#   db-1       | 2026-06-23 10:23:45 ERROR  could not connect to peer
#   worker-1   | Traceback (most recent call last):
# The prefix is the service/container name, left-padded to a common width.
_PREFIX_RE = re.compile(r"^(?P<service>[A-Za-z0-9][\w.\-]*)\s+\|\s(?P<body>.*)$")
_TS_RE = re.compile(
    r"\b(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)


class ComposeLogParser(LogParser):
    FORMAT_NAME = "composelog"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        considered = 0
        matched = 0
        services: set[str] = set()
        for line in sample_lines[:25]:
            if not line.strip():
                continue
            considered += 1
            m = _PREFIX_RE.match(line)
            if m:
                matched += 1
                services.add(m["service"])
        # Compose prefixes dominate the stream; a single "a | b" table row in
        # some other log should not qualify, so require a real majority.
        return considered > 0 and matched >= 2 and matched * 2 >= considered

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PREFIX_RE.match(line)
        if not m:
            return None
        service = m["service"]
        body = m["body"].rstrip()
        ts = None
        sev_text = body
        tsm = _TS_RE.search(body)
        if tsm:
            try:
                ts = dateparser.parse(tsm["ts"].replace(",", "."))
            except (ValueError, TypeError, OverflowError):
                ts = None
            # Drop the timestamp before inferring severity: a trailing "HH:MM:SS"
            # ends in digits, which would otherwise make the next level token
            # ("10:23:48 ERROR") look like a count and be ignored.
            sev_text = (body[: tsm.start()] + " " + body[tsm.end():]).strip()
        severity = _extract_severity(sev_text)
        if severity is Severity.UNKNOWN:
            severity = Severity.INFO
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=service,
            message=body,
            raw=line,
            line_number=line_number,
            extra={"service": service},
        )
