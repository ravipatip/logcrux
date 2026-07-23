from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser


# AWS CloudTrail records, one JSON event per line (the shape produced when
# CloudTrail is delivered to CloudWatch Logs / flattened from the S3 objects):
#   {"eventVersion":"1.08","eventTime":"2026-06-23T10:23:45Z",
#    "eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin",
#    "awsRegion":"us-east-1","sourceIPAddress":"1.2.3.4",
#    "userIdentity":{"type":"IAMUser","userName":"alice"},
#    "errorCode":"AccessDenied","responseElements":{...}}
def _is_cloudtrail(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "eventSource" in obj
        and "eventName" in obj
        and "eventTime" in obj
    )


class CloudTrailParser(LogParser):
    FORMAT_NAME = "cloudtrail"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and "cloudtrail" in str(path).lower():
            return True
        for line in sample_lines[:10]:
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            if _is_cloudtrail(obj):
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
        if not _is_cloudtrail(obj):
            return None
        ts: datetime | None
        try:
            ts = dateparser.parse(str(obj["eventTime"]))
        except (ValueError, TypeError, OverflowError):
            ts = None
        identity = obj.get("userIdentity", {})
        actor = ""
        if isinstance(identity, dict):
            actor = str(
                identity.get("userName")
                or identity.get("arn")
                or identity.get("type")
                or ""
            )
        error_code = obj.get("errorCode")
        error_msg = obj.get("errorMessage")
        # A failed/denied API call is the security-relevant signal CloudTrail is
        # mined for; surface it as a warning so anomaly detection can cluster it.
        severity = Severity.WARNING if error_code else Severity.INFO
        message = f"{obj['eventName']} {obj['eventSource']}"
        if actor:
            message += f" by {actor}"
        if obj.get("sourceIPAddress"):
            message += f" from {obj['sourceIPAddress']}"
        if error_code:
            message += f" -> {error_code}"
            if error_msg:
                message += f": {error_msg}"
        extra: dict[str, object] = {
            "event_name": obj["eventName"],
            "event_source": obj["eventSource"],
            "aws_region": obj.get("awsRegion"),
            "source_ip": obj.get("sourceIPAddress"),
        }
        if error_code:
            extra["error_code"] = error_code
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="cloudtrail",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
