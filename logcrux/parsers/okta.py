from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Okta System Log (the SaaS identity provider's audit feed) — JSON events:
#   {"uuid":"...","published":"2026-06-28T10:15:01.123Z",
#    "eventType":"user.session.start","severity":"INFO",
#    "displayMessage":"User login to Okta",
#    "actor":{"id":"...","alternateId":"bob@x.com","displayName":"Bob"},
#    "outcome":{"result":"SUCCESS"},"client":{"ipAddress":"1.2.3.4"}}
# Distinguished by eventType + actor + published.
_SEVERITY = {
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARN": Severity.WARNING,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
}


def _is_okta(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "eventType" in obj
        and "actor" in obj
        and ("published" in obj or "uuid" in obj)
    )


class OktaParser(LogParser):
    FORMAT_NAME = "okta"

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
            if _is_okta(obj):
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
        if not _is_okta(obj):
            return None
        ts = None
        pub = obj.get("published")
        if isinstance(pub, str):
            try:
                ts = datetime.fromisoformat(pub.replace("Z", "+00:00"))
            except ValueError:
                ts = None
        outcome = obj.get("outcome")
        result = outcome.get("result") if isinstance(outcome, dict) else None
        severity = _SEVERITY.get(str(obj.get("severity", "")).upper(), Severity.INFO)
        # A FAILURE/DENY outcome is at least a warning even if Okta tags it INFO.
        if isinstance(result, str) and result.upper() not in ("SUCCESS", "ALLOW"):
            if severity in (Severity.DEBUG, Severity.INFO):
                severity = Severity.WARNING
        actor = obj.get("actor")
        actor_id = actor.get("alternateId") if isinstance(actor, dict) else None
        client = obj.get("client")
        ip = client.get("ipAddress") if isinstance(client, dict) else None
        message = str(obj.get("displayMessage") or obj.get("eventType", ""))
        extra: dict[str, object] = {
            "eventType": obj.get("eventType"),
            "actor": actor_id,
            "result": result,
            "client_ip": ip,
        }
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="okta",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
