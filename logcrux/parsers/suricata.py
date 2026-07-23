from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Suricata EVE JSON (eve.json) — one JSON event per line, keyed by
# "event_type" (alert / flow / dns / http / tls / anomaly / ...):
#   {"timestamp":"2026-06-20T10:15:01.123456+0000","flow_id":1,"event_type":"alert",
#    "src_ip":"1.2.3.4","dest_ip":"5.6.7.8","alert":{"signature":"ET SCAN",
#    "category":"Attempted Recon","severity":2}}
# Alert priority severity: 1 = high, 2 = medium, 3 = low.
_ALERT_SEVERITY: dict[int, Severity] = {
    1: Severity.CRITICAL,
    2: Severity.ERROR,
    3: Severity.WARNING,
}


def _is_eve(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "event_type" in obj
        and "timestamp" in obj
        and ("src_ip" in obj or "flow_id" in obj or "alert" in obj)
    )


class SuricataParser(LogParser):
    FORMAT_NAME = "suricata"

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
            if _is_eve(obj):
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
        if not _is_eve(obj):
            return None
        ts = None
        t_raw = obj.get("timestamp")
        if isinstance(t_raw, str):
            try:
                ts = dateparser.parse(t_raw)
            except (ValueError, TypeError, OverflowError):
                ts = None
        event_type = str(obj.get("event_type", ""))
        src = obj.get("src_ip")
        dest = obj.get("dest_ip")
        extra: dict[str, object] = {"event_type": event_type}
        if src:
            extra["src_ip"] = src
        if dest:
            extra["dest_ip"] = dest
        if event_type == "alert" and isinstance(obj.get("alert"), dict):
            alert = obj["alert"]
            sig = str(alert.get("signature", "alert"))
            prio = alert.get("severity")
            severity = (
                _ALERT_SEVERITY.get(int(prio), Severity.WARNING)
                if isinstance(prio, int)
                else Severity.WARNING
            )
            extra["signature"] = sig
            if "category" in alert:
                extra["category"] = alert["category"]
            message = f"Alert: {sig}"
            if src and dest:
                message += f" ({src} -> {dest})"
        elif event_type == "anomaly":
            severity = Severity.WARNING
            anomaly = obj.get("anomaly")
            detail = ""
            if isinstance(anomaly, dict):
                detail = str(anomaly.get("event", ""))
            message = f"Anomaly: {detail}".rstrip(": ")
        else:
            severity = Severity.INFO
            message = f"{event_type} {src or ''} -> {dest or ''}".strip()
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="suricata",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
