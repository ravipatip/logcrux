from __future__ import annotations

import json
import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.apache_access import _status_severity
from logcrux.parsers.base import LogParser

# A JSON access-log line carries the request as "METHOD /path HTTP/x.y" plus an
# HTTP status code. This is the very common `log_format json` / escaped-JSON
# access log emitted by nginx/openresty (and shipped through ELK/Loki/Fluentd
# pipelines). It was falling to the generic parser, which can't read the status
# code — so a 5xx burst in JSON logs was reported CLEAN while the identical burst
# in a plain combined-format log was correctly flagged.
_REQUEST_RE = re.compile(r"^[A-Z]+ \S+ HTTP/\d")

# Accept the usual key-name variants across nginx templates.
_TIME_KEYS = ("time_iso8601", "time_local", "time", "timestamp", "@timestamp")
_STATUS_KEYS = ("status", "response")
_REQUEST_KEYS = ("request", "request_line")
_CLIENT_KEYS = ("remote_addr", "remote_ip", "client_ip", "clientip")
_BYTES_KEYS = ("body_bytes_sent", "bytes_sent", "bytes", "response_bytes")


def _first(d: dict[str, object], keys: tuple[str, ...]) -> object | None:
    for k in keys:
        if k in d and d[k] not in (None, "", "-"):
            val: object = d[k]
            return val
    return None


def _status_int(d: dict[str, object]) -> int | None:
    status = _first(d, _STATUS_KEYS)
    if isinstance(status, bool):  # bool is an int subclass — reject it
        return None
    if isinstance(status, int):
        return status
    if isinstance(status, str) and status.isdigit():
        return int(status)
    return None


def _parse_obj(line: str) -> dict[str, object] | None:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    request = _first(obj, _REQUEST_KEYS)
    if not isinstance(request, str) or not _REQUEST_RE.match(request):
        return None
    if _status_int(obj) is None:
        return None
    return obj


class JsonAccessParser(LogParser):
    FORMAT_NAME = "json-access"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return any(_parse_obj(line) is not None for line in sample_lines[:5] if line.strip())

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line.strip():
            return None
        obj = _parse_obj(line)
        if obj is None:
            return None
        status = _status_int(obj)
        assert status is not None  # guaranteed by _parse_obj
        request = str(_first(obj, _REQUEST_KEYS))
        ts = None
        raw_ts = _first(obj, _TIME_KEYS)
        if isinstance(raw_ts, str):
            try:
                ts = dateparser.parse(raw_ts, fuzzy=True)
            except (ValueError, OverflowError):
                ts = None
        parts = request.split()
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else ""
        extra: dict[str, object] = {"status_code": status, "method": method, "path": path}
        client = _first(obj, _CLIENT_KEYS)
        if client is not None:
            extra["client_ip"] = client
        nbytes = _first(obj, _BYTES_KEYS)
        if nbytes is not None:
            extra["response_bytes"] = nbytes
        return ParsedEvent(
            timestamp=ts,
            severity=_status_severity(status),
            source="nginx",
            message=f"{method} {path} {status}".strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
