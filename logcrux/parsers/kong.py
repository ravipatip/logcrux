from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser


# Kong API Gateway access log (the default `file-log`/`http-log` JSON schema):
#   {"client_ip":"1.2.3.4","started_at":1782000901000,
#    "request":{"method":"GET","uri":"/api","size":120},
#    "response":{"status":200,"size":512},
#    "latencies":{"request":12,"kong":3,"proxy":9},
#    "service":{"name":"orders","host":"orders.svc"},
#    "route":{"name":"orders-route"}}
# Distinguished by the latencies + request + response triad (Kong-specific).
def _is_kong(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("latencies"), dict)
        and isinstance(obj.get("request"), dict)
        and isinstance(obj.get("response"), dict)
    )


class KongParser(LogParser):
    FORMAT_NAME = "kong"

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
            if _is_kong(obj):
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
        if not _is_kong(obj):
            return None
        ts = None
        started = obj.get("started_at")
        if isinstance(started, (int, float)):
            try:
                ts = datetime.fromtimestamp(started / 1000, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                ts = None
        request = obj.get("request", {})
        response = obj.get("response", {})
        status = response.get("status")
        severity = Severity.INFO
        if isinstance(status, int):
            if status >= 500:
                severity = Severity.ERROR
            elif status >= 400:
                severity = Severity.WARNING
        service = obj.get("service") or {}
        route = obj.get("route") or {}
        message = (
            f"{request.get('method', '')} {request.get('uri', '')} "
            f"{status}"
        ).strip()
        extra: dict[str, object] = {
            "client_ip": obj.get("client_ip"),
            "status": status,
            "service": service.get("name") if isinstance(service, dict) else None,
            "route": route.get("name") if isinstance(route, dict) else None,
            "latencies": obj.get("latencies"),
        }
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="kong",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
