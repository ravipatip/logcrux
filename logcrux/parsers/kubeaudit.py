from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser


# Kubernetes API server audit log — one JSON Event per line:
#   {"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata",
#    "stage":"ResponseComplete","requestURI":"/api/v1/namespaces/default/pods",
#    "verb":"create","user":{"username":"system:serviceaccount:default:deployer"},
#    "sourceIPs":["10.0.0.1"],"objectRef":{"resource":"pods","namespace":"default"},
#    "responseStatus":{"code":403,"reason":"Forbidden"},
#    "requestReceivedTimestamp":"2026-06-23T10:23:45.123Z"}
def _is_kube_audit(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and obj.get("kind") == "Event"
        and str(obj.get("apiVersion", "")).startswith("audit.k8s.io")
    )


class KubeAuditParser(LogParser):
    FORMAT_NAME = "kubeaudit"

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
            if _is_kube_audit(obj):
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
        if not _is_kube_audit(obj):
            return None
        ts: datetime | None = None
        raw_ts = obj.get("requestReceivedTimestamp") or obj.get("stageTimestamp")
        if isinstance(raw_ts, str):
            try:
                ts = dateparser.parse(raw_ts)
            except (ValueError, TypeError, OverflowError):
                ts = None
        user = obj.get("user", {})
        username = user.get("username", "?") if isinstance(user, dict) else "?"
        verb = obj.get("verb", "?")
        uri = obj.get("requestURI", "")
        status = obj.get("responseStatus", {})
        code = status.get("code") if isinstance(status, dict) else None
        # 401/403 (authn/authz failures) and 5xx are the security-relevant audit
        # events; surface them above benign reads so clustering can catch abuse.
        severity = Severity.INFO
        if isinstance(code, int):
            if code in (401, 403):
                severity = Severity.WARNING
            elif code >= 500:
                severity = Severity.ERROR
        message = f"{verb} {uri} by {username}"
        if code is not None:
            message += f" -> {code}"
        extra: dict[str, object] = {
            "verb": verb,
            "user": username,
            "stage": obj.get("stage"),
            "response_code": code,
        }
        source_ips = obj.get("sourceIPs")
        if isinstance(source_ips, list) and source_ips:
            extra["source_ip"] = source_ips[0]
            message += f" from {source_ips[0]}"
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="kube-apiserver-audit",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
