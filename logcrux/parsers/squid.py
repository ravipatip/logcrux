from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

_NATIVE_DETECT = re.compile(r"^\d{9,10}\.\d{3}\s+\d+\s+\S+\s+[A-Z_]+/\d{3}")

# Squid CLF looks like a web-server access log, but the request target is an
# absolute URL (a forward proxy logs `GET http://host/...`) or a CONNECT
# tunnel (`CONNECT host:443`). Web servers log a path (`GET /...`), so the
# scheme / CONNECT marker is what distinguishes a proxy log from nginx/apache.
_CLF_PROXY_DETECT = re.compile(
    r'^\S+ \S+ \S+ \[[^\]]+\] "(?:CONNECT \S+:\d+|\S+ [a-z][a-z0-9+.-]*://\S+) '
)

_NATIVE_PATTERN = re.compile(
    r"(?P<timestamp>\d{9,10}\.\d{3})\s+"
    r"(?P<duration>\d+)\s+"
    r"(?P<client_ip>\S+)\s+"
    r"(?P<result>[A-Z_]+)/(?P<status>\d{3})\s+"
    r"(?P<bytes>\d+)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<url>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<hierarchy>[A-Z_]+)/(?P<upstream>\S+)\s+"
    r"(?P<content_type>\S+)"
)

_CLF_PATTERN = re.compile(
    r"(?P<client_ip>\S+) \S+ (?P<ident>\S+) "
    r"\[(?P<timestamp>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r"(?P<status>\d{3}) (?P<bytes>\S+)"
)


def _native_severity(result: str, status: int) -> Severity:
    if "DENIED" in result:
        return Severity.WARNING
    if status == 407:
        return Severity.WARNING
    if status >= 500:
        return Severity.ERROR
    if status >= 400:
        return Severity.WARNING
    return Severity.INFO


def _clf_severity(status: int) -> Severity:
    if status == 407:
        return Severity.WARNING
    if status >= 500:
        return Severity.ERROR
    if status >= 400:
        return Severity.WARNING
    return Severity.INFO


def _extract_connect_port(url: str) -> int | None:
    if ":" in url and not url.startswith("http"):
        try:
            return int(url.rsplit(":", 1)[-1])
        except ValueError:
            return None
    return None


class SquidParser(LogParser):
    FORMAT_NAME = "squid"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path:
            path_str = str(path).lower()
            if "squid" in path_str or "proxy" in path_str:
                return True
        return any(
            _NATIVE_DETECT.match(line) or _CLF_PROXY_DETECT.match(line)
            for line in sample_lines[:5]
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _NATIVE_PATTERN.match(line)
        if m:
            return self._parse_native(m, line, line_number)
        m = _CLF_PATTERN.match(line)
        if m:
            return self._parse_clf(m, line, line_number)
        return None

    def _parse_native(
        self, m: re.Match[str], line: str, line_number: int
    ) -> ParsedEvent:
        result = m["result"]
        status = int(m["status"])
        method = m["method"]
        url = m["url"]
        connect_port = _extract_connect_port(url) if method == "CONNECT" else None
        try:
            ts = datetime.fromtimestamp(float(m["timestamp"]), tz=UTC)
        except Exception:
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_native_severity(result, status),
            source="squid",
            message=f"{method} {url} {result}/{status}",
            raw=line,
            line_number=line_number,
            extra={
                "parser": "squid",
                "client_ip": m["client_ip"],
                "duration_ms": int(m["duration"]),
                "result_code": result,
                "status_code": status,
                "bytes": int(m["bytes"]),
                "method": method,
                "url": url,
                "ident": m["ident"],
                "hierarchy": m["hierarchy"],
                "upstream_ip": m["upstream"],
                "content_type": m["content_type"],
                "connect_port": connect_port,
            },
        )

    def _parse_clf(
        self, m: re.Match[str], line: str, line_number: int
    ) -> ParsedEvent:
        status = int(m["status"])
        method = m["method"]
        url = m["url"]
        connect_port = _extract_connect_port(url) if method == "CONNECT" else None
        try:
            ts = dateparser.parse(m["timestamp"], fuzzy=True)
        except Exception:
            ts = None
        return ParsedEvent(
            timestamp=ts,
            severity=_clf_severity(status),
            source="squid",
            message=f"{method} {url} {status}",
            raw=line,
            line_number=line_number,
            extra={
                "parser": "squid",
                "client_ip": m["client_ip"],
                "result_code": None,
                "status_code": status,
                "method": method,
                "url": url,
                "ident": m["ident"],
                "connect_port": connect_port,
            },
        )
