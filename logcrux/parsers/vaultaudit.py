from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser


# HashiCorp Vault audit device (file backend) — one JSON object per line. Every
# request and response to Vault is logged here (HMAC-obscured), e.g.:
#   {"time":"2026-06-23T10:23:45.123Z","type":"response","auth":{...},
#    "request":{"operation":"read","path":"secret/data/db","remote_address":"10.0.0.1"},
#    "response":{"status":403},"error":"permission denied"}
def _is_vault_audit(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and obj.get("type") in ("request", "response")
        and "auth" in obj
        and "request" in obj
    )


class VaultAuditParser(LogParser):
    FORMAT_NAME = "vaultaudit"

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
            if _is_vault_audit(obj):
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
        if not _is_vault_audit(obj):
            return None
        ts: datetime | None = None
        raw_ts = obj.get("time")
        if isinstance(raw_ts, str):
            try:
                ts = dateparser.parse(raw_ts)
            except (ValueError, TypeError, OverflowError):
                ts = None
        request = obj.get("request", {}) if isinstance(obj.get("request"), dict) else {}
        operation = request.get("operation", "?")
        path_str = request.get("path", "?")
        remote = request.get("remote_address", "")
        error = obj.get("error")
        severity = Severity.WARNING if error else Severity.INFO
        message = f"{obj['type']} {operation} {path_str}"
        if remote:
            message += f" from {remote}"
        if error:
            message += f" -> {error}"
        extra: dict[str, object] = {
            "audit_type": obj["type"],
            "operation": operation,
            "path": path_str,
        }
        if error:
            extra["error"] = error
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="vault-audit",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
