from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Google Cloud Logging / Stackdriver structured entries, one JSON object per
# line (as exported to a file or via ``gcloud logging read --format=json``):
#   {"severity":"ERROR","timestamp":"2026-06-23T10:23:45.123Z",
#    "logName":"projects/p/logs/run.googleapis.com%2Fstderr",
#    "resource":{"type":"cloud_run_revision"},
#    "textPayload":"connection refused"}
# Severity scale: DEFAULT/DEBUG/INFO/NOTICE/WARNING/ERROR/CRITICAL/ALERT/EMERGENCY
_SEVERITY_MAP: dict[str, Severity] = {
    "DEFAULT": Severity.INFO,
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "NOTICE": Severity.INFO,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "CRITICAL": Severity.CRITICAL,
    "ALERT": Severity.CRITICAL,
    "EMERGENCY": Severity.CRITICAL,
}
_GCP_MARKERS = ("logName", "resource", "jsonPayload", "textPayload", "insertId")


def _is_gcp(obj: object) -> bool:
    if not isinstance(obj, dict):
        return False
    return (
        "severity" in obj
        and "timestamp" in obj
        and any(k in obj for k in _GCP_MARKERS)
    )


def _payload_message(obj: dict[str, object]) -> str:
    text = obj.get("textPayload")
    if isinstance(text, str) and text:
        return text
    payload = obj.get("jsonPayload")
    if isinstance(payload, dict):
        msg = payload.get("message") or payload.get("msg") or payload.get("event")
        if isinstance(msg, str) and msg:
            return msg
        return json.dumps(payload, separators=(",", ":"))
    proto = obj.get("protoPayload")
    if isinstance(proto, dict):
        msg = proto.get("status", {})
        if isinstance(msg, dict) and msg.get("message"):
            return str(msg["message"])
        return json.dumps(proto, separators=(",", ":"))[:500]
    return ""


class GCPParser(LogParser):
    FORMAT_NAME = "gcp"

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
            if _is_gcp(obj):
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
        if not _is_gcp(obj):
            return None
        ts: datetime | None
        try:
            ts = dateparser.parse(str(obj["timestamp"]))
        except (ValueError, TypeError, OverflowError):
            ts = None
        severity_str = str(obj.get("severity", "DEFAULT")).upper()
        resource = obj.get("resource")
        res_type = ""
        if isinstance(resource, dict):
            res_type = str(resource.get("type", ""))
        extra: dict[str, object] = {"severity": severity_str}
        if res_type:
            extra["resource_type"] = res_type
        if obj.get("logName"):
            extra["log_name"] = obj["logName"]
        return ParsedEvent(
            timestamp=ts,
            severity=_SEVERITY_MAP.get(severity_str, Severity.INFO),
            source=res_type or "gcp",
            message=_payload_message(obj).strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
