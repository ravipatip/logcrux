from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# PingAuthorize (formerly PingDataGovernance) policy-decision log —
# <PingAuthorize>/logs/policy-decision — one JSON object per line describing an
# authorization decision. Two shapes ship:
#
#   server PDP:  {"requestId":"8245be35-...","timeStamp":"2023-11-14T03:21:47.7Z",
#                 "elapsedTime":22,"results":[{"attribute":"action","value":"delete",
#                 "decision":"PERMIT"}]}
#   gateway:     {"id":"cda6fd43-...","timestamp":"2024-08-13T10:48:45.3Z",
#                 "elapsedTime":649161,"decision":"PERMIT","authorised":true,...}
#
# Distinguished by an elapsedTime field plus a PERMIT/DENY/INDETERMINATE decision
# (top-level or inside results[]/result[]) — a marker no other JSON logger emits.
# NB the PingAuthorize/PingDirectory *server* error logs use the bracketed
# category=/severity= Ping Data platform shape and are handled by the
# ``pingdirectory`` parser; this one is only the JSON decision feed.
_DECISION_VALUES = {"PERMIT", "DENY", "INDETERMINATE", "NOT_APPLICABLE"}


def _decisions(obj: dict[str, object]) -> list[str]:
    """Collect every decision string in the record (top-level or nested)."""
    found: list[str] = []
    top = obj.get("decision")
    if isinstance(top, str):
        found.append(top)
    for key in ("results", "result"):
        arr = obj.get(key)
        if isinstance(arr, list):
            found.extend(
                r["decision"]
                for r in arr
                if isinstance(r, dict) and isinstance(r.get("decision"), str)
            )
    return found


def _is_decision_log(obj: object) -> bool:
    if not isinstance(obj, dict):
        return False
    if "elapsedTime" not in obj and "requestId" not in obj:
        return False
    return any(d.upper() in _DECISION_VALUES for d in _decisions(obj))


class PingAuthorizeParser(LogParser):
    FORMAT_NAME = "pingauthorize"

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
            if _is_decision_log(obj):
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
        if not _is_decision_log(obj):
            return None

        ts = None
        raw_ts = obj.get("timeStamp") or obj.get("timestamp")
        if isinstance(raw_ts, str):
            try:
                ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                ts = None

        decisions = [d.upper() for d in _decisions(obj)]
        # A DENY (or INDETERMINATE — policy couldn't reach a verdict) is a
        # security-relevant outcome; a clean PERMIT is informational.
        if any(d in ("DENY", "INDETERMINATE") for d in decisions):
            severity = Severity.WARNING
            verdict = "DENY" if "DENY" in decisions else "INDETERMINATE"
        else:
            severity = Severity.INFO
            verdict = decisions[0] if decisions else "PERMIT"

        req_id = obj.get("requestId") or obj.get("id")
        message = f"Policy decision {verdict}"
        if req_id:
            message += f" (requestId={req_id})"
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="pingauthorize",
            message=message,
            raw=line,
            line_number=line_number,
            extra={
                "decision": verdict,
                "requestId": req_id,
                "elapsedTime": obj.get("elapsedTime"),
            },
        )
