from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser


# Cloudflare Logpush HTTP-request logs — JSON, one request per line:
#   {"ClientIP":"1.2.3.4","ClientRequestHost":"example.com",
#    "ClientRequestMethod":"GET","ClientRequestURI":"/api","EdgeResponseStatus":200,
#    "EdgeStartTimestamp":"2026-06-28T10:15:01Z","RayID":"8a1b...",
#    "WAFAction":"allow","OriginResponseStatus":200}
# Distinguished by the RayID + EdgeResponseStatus pair (Cloudflare-specific).
def _is_cloudflare(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "RayID" in obj
        and ("EdgeResponseStatus" in obj or "EdgeStartTimestamp" in obj)
    )


def _status_severity(status: object, waf: object) -> Severity:
    if isinstance(waf, str) and waf.lower() in ("block", "drop", "challenge"):
        return Severity.WARNING
    if isinstance(status, int):
        if status >= 500:
            return Severity.ERROR
        if status >= 400:
            return Severity.WARNING
    return Severity.INFO


class CloudflareParser(LogParser):
    FORMAT_NAME = "cloudflare"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for line in sample_lines[:10]:
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            if _is_cloudflare(obj):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        stripped = line.strip()
        if not stripped.startswith("{"):
            return None
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return None
        if not _is_cloudflare(obj):
            return None
        ts = None
        raw_ts = obj.get("EdgeStartTimestamp")
        if isinstance(raw_ts, str):
            try:
                ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                ts = None
        elif isinstance(raw_ts, (int, float)):
            try:
                ts = datetime.fromtimestamp(raw_ts / 1e9, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                ts = None
        status = obj.get("EdgeResponseStatus")
        waf = obj.get("WAFAction")
        method = obj.get("ClientRequestMethod", "")
        host = obj.get("ClientRequestHost", "")
        uri = obj.get("ClientRequestURI", "")
        message = f"{method} {host}{uri} {status}".strip()
        extra: dict[str, object] = {
            "client_ip": obj.get("ClientIP"),
            "status": status,
            "ray_id": obj.get("RayID"),
            "waf_action": waf,
        }
        return ParsedEvent(
            timestamp=ts,
            severity=_status_severity(status, waf),
            source=str(host or "cloudflare"),
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
