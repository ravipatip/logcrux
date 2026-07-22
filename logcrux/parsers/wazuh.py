from __future__ import annotations

import json
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Wazuh / OSSEC JSON alerts (alerts.json) — one alert per line carrying a
# "rule" object (with a numeric "level" 0-15) and an "agent"/"manager":
#   {"timestamp":"2026-06-20T10:15:01.123+0000","rule":{"level":5,"description":
#    "sshd: authentication failed","id":"5710"},"agent":{"name":"web01"},
#    "full_log":"Failed password for root from 1.2.3.4"}
# Rule level mapping (Wazuh convention): 0-3 low, 4-7 medium, 8-11 high,
# 12-15 critical.


def _is_wazuh(obj: object) -> bool:
    rule = obj.get("rule") if isinstance(obj, dict) else None
    return (
        isinstance(obj, dict)
        and isinstance(rule, dict)
        and "level" in rule
        and ("agent" in obj or "manager" in obj)
    )


def _level_severity(level: int) -> Severity:
    if level >= 12:
        return Severity.CRITICAL
    if level >= 8:
        return Severity.ERROR
    if level >= 4:
        return Severity.WARNING
    return Severity.INFO


class WazuhParser(LogParser):
    FORMAT_NAME = "wazuh"

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
            if _is_wazuh(obj):
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
        if not _is_wazuh(obj):
            return None
        rule = obj["rule"]
        try:
            level = int(rule.get("level", 0))
        except (TypeError, ValueError):
            level = 0
        ts = None
        t_raw = obj.get("timestamp")
        if isinstance(t_raw, str):
            try:
                ts = dateparser.parse(t_raw)
            except (ValueError, TypeError, OverflowError):
                ts = None
        message = str(rule.get("description", "")) or str(obj.get("full_log", ""))
        extra: dict[str, object] = {"rule_level": level}
        if "id" in rule:
            extra["rule_id"] = rule["id"]
        agent = obj.get("agent")
        if isinstance(agent, dict) and "name" in agent:
            extra["agent"] = agent["name"]
        for group in ("srcip", "dstuser", "srcuser"):
            data = obj.get("data")
            if isinstance(data, dict) and group in data:
                extra[group] = data[group]
        return ParsedEvent(
            timestamp=ts,
            severity=_level_severity(level),
            source="wazuh",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
