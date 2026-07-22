from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# AWS S3 server access log. Space-delimited positional fields with a 64-hex
# bucket-owner, the bucket, a "[dd/Mon/yyyy:HH:MM:SS +0000]" stamp, the remote
# IP, requester, request-id, and a "REST.<OP>.<RESOURCE>" operation:
#   79a5..e bucket [28/Jun/2026:10:15:01 +0000] 1.2.3.4 arn:.. ID
#       REST.GET.OBJECT key "GET /key HTTP/1.1" 200 - 1234 1234 ...
# The 64-hex owner + bracketed date + "REST.<verb>." token is the signature.
_PATTERN = re.compile(
    r"^(?P<owner>[0-9a-f]{64}) (?P<bucket>\S+) "
    r"\[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "
    r"(?P<remote_ip>\S+) (?P<requester>\S+) (?P<request_id>\S+) "
    r"(?P<operation>REST\.\w+\.\w+) (?P<key>\S+) "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}|-) (?P<error>\S+) '
    r"(?P<bytes_sent>\S+)"
)


def _severity(status: str) -> Severity:
    if not status.isdigit():
        return Severity.INFO
    code = int(status)
    if code >= 500:
        return Severity.ERROR
    if code in (403, 404) or code >= 400:
        return Severity.WARNING
    return Severity.INFO


class S3AccessParser(LogParser):
    FORMAT_NAME = "s3access"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_PATTERN.match(ln) for ln in sample_lines[:20])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"].replace(":", " ", 1))
        except (ValueError, TypeError, OverflowError):
            ts = None
        status = m["status"]
        message = (
            f"{m['operation']} {m['key']} {status} "
            f"(\"{m['request']}\") from {m['remote_ip']}"
        )
        extra: dict[str, object] = {
            "bucket": m["bucket"],
            "operation": m["operation"],
            "status": int(status) if status.isdigit() else None,
            "remote_ip": m["remote_ip"],
            "error_code": None if m["error"] == "-" else m["error"],
            "request_id": m["request_id"],
        }
        return ParsedEvent(
            timestamp=ts,
            severity=_severity(status),
            source="s3",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
