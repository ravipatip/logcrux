from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Fortinet FortiGate firewall logs — space-separated key=value pairs (values may
# be quoted), optionally behind a syslog header:
#   date=2026-06-20 time=10:15:01 devname="FW01" devid="FG100D" logid="0100032001"
#   type="event" subtype="system" level="warning" vd="root" msg="interface down"
# The date= + time= + devid=/logid= + type= signature is unmistakable. "level"
# is the FortiOS severity word (emergency..debug).
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
_LEVEL_MAP = {
    "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "notice": Severity.INFO,
    "information": Severity.INFO,
    "informational": Severity.INFO,
    "debug": Severity.DEBUG,
}


def _parse_kv(line: str) -> dict[str, str]:
    return {k: (q if q != "" or v is None else v) for k, q, v in _KV_RE.findall(line)}


class FortiGateParser(LogParser):
    FORMAT_NAME = "fortigate"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if "date=" in ln and "time=" in ln and "type=" in ln and (
                "devid=" in ln or "logid=" in ln
            ):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        kv = _parse_kv(line)
        if "date" not in kv or "time" not in kv or "type" not in kv:
            return None
        ts = None
        try:
            ts = dateparser.parse(f"{kv['date']} {kv['time']}")
        except (ValueError, TypeError, OverflowError):
            ts = None
        level = kv.get("level", "").lower()
        severity = _LEVEL_MAP.get(level, Severity.INFO)
        # A blocked/denied action escalates even an "notice"-level traffic log.
        action = kv.get("action", "").lower()
        if action in {"deny", "blocked", "drop", "block"} and severity == Severity.INFO:
            severity = Severity.WARNING
        message = kv.get("msg") or kv.get("logdesc") or kv.get("subtype") or kv.get("type")
        extra: dict[str, object] = {
            "log_type": kv.get("type"),
            "subtype": kv.get("subtype"),
            "level": level or None,
        }
        for key in ("srcip", "dstip", "action", "devname"):
            if key in kv:
                extra[key] = kv[key]
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="fortigate",
            message=str(message),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
