from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

_PRIORITY_MAP: dict[str, Severity] = {
    "0": Severity.CRITICAL, "1": Severity.CRITICAL, "2": Severity.CRITICAL,
    "3": Severity.ERROR,
    "4": Severity.WARNING,
    "5": Severity.INFO, "6": Severity.INFO,
    "7": Severity.DEBUG,
}


class JournaldParser(LogParser):
    FORMAT_NAME = "journald"

    # Keys unique to `journalctl --output=json` export, used to tell a journald
    # JSON line apart from other JSON log formats (e.g. MongoDB structured logs).
    _JOURNALD_KEYS = ("__REALTIME_TIMESTAMP", "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER",
                      "_BOOT_ID", "_MACHINE_ID", "PRIORITY")

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for line in sample_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.startswith("{"):
                return False
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                return False
            # A journald export object carries "MESSAGE" plus at least one
            # journald-specific metadata key; MongoDB JSON has neither.
            return isinstance(obj, dict) and "MESSAGE" in obj and any(
                k in obj for k in cls._JOURNALD_KEYS
            )
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line.strip():
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        message = data.get("MESSAGE", "")
        if isinstance(message, list):
            # journald encodes non-UTF8 binary fields as arrays of byte integers
            message = bytes(message).decode("utf-8", errors="replace")
        if not message:
            return None
        ts = None
        raw_ts = data.get("__REALTIME_TIMESTAMP")
        if raw_ts:
            try:
                ts = datetime.fromtimestamp(int(raw_ts) / 1_000_000, tz=UTC)
            except Exception:
                pass
        priority = str(data.get("PRIORITY", "6"))
        severity = _PRIORITY_MAP.get(priority, Severity.UNKNOWN)
        source = data.get("SYSLOG_IDENTIFIER") or data.get("_COMM") or "unknown"
        extra = {k: v for k, v in data.items()
                 if k not in ("MESSAGE", "__REALTIME_TIMESTAMP", "PRIORITY",
                              "SYSLOG_IDENTIFIER", "__MONOTONIC_TIMESTAMP")}
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=source,
            message=str(message),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
