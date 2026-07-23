from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# ModSecurity (WAF) JSON audit log — one transaction per line, keyed by the
# "transaction" + "audit_data" objects:
#   {"transaction":{"time":"20/Jun/2026:10:15:01 +0000","client_ip":"1.2.3.4",
#    "request":{"method":"GET","uri":"/?id=1' OR 1=1"}},"audit_data":{"messages":
#    ["Warning. Pattern match ... [id \"942100\"] [msg \"SQL Injection\"]
#    [severity \"CRITICAL\"]"]}}


def _is_modsec(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("transaction"), dict)
        and "audit_data" in obj
    )


class ModSecurityParser(LogParser):
    FORMAT_NAME = "modsecurity"

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
            if _is_modsec(obj):
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
        if not _is_modsec(obj):
            return None
        txn = obj["transaction"]
        ts = None
        t_raw = txn.get("time")
        if isinstance(t_raw, str):
            try:
                # ModSecurity uses Apache's "DD/Mon/YYYY:HH:MM:SS +zzzz".
                ts = dateparser.parse(t_raw.replace(":", " ", 1))
            except (ValueError, TypeError, OverflowError):
                ts = None
        audit = obj.get("audit_data")
        messages = audit.get("messages", []) if isinstance(audit, dict) else []
        request = txn.get("request") if isinstance(txn.get("request"), dict) else {}
        method = request.get("method", "")
        uri = request.get("uri", "")
        extra: dict[str, object] = {}
        if txn.get("client_ip"):
            extra["client_ip"] = txn["client_ip"]
        # Severity: any blocking/critical message escalates; warnings -> warning.
        severity = Severity.INFO
        joined = " ".join(str(m) for m in messages)
        low = joined.lower()
        if 'severity "critical"' in low or "access denied" in low or "[severity \"0\"]" in low:
            severity = Severity.CRITICAL
        elif messages:
            severity = Severity.WARNING
        if messages:
            extra["messages"] = len(messages)
        message = f"{method} {uri}".strip()
        if messages:
            first = str(messages[0])
            message = f"WAF: {first[:200]}" if not message else f"{message} — {first[:160]}"
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="modsecurity",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
