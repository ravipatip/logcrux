from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# Structured application logs with no dedicated parser: one JSON object per
# line carrying a level and a message under one of the common key names.
# python structlog (real, lab/apps7, 2026-10-20) was read as generic text, so
# '"level": "critical"' graded nothing and the app's fatal exit went unnamed:
#   {"service": "billing", "event": "giving up: database unreachable",
#    "level": "critical", "timestamp": "2026-10-19T23:40:17.921225Z"}
# The same shape comes from Go zap/slog/zerolog, logrus/loguru JSON, Rust
# tracing-subscriber JSON and most "log as JSON" settings. Checked after every
# format-specific JSON parser (pino, bunyan, winston, serilog, ...).
_LEVEL_KEYS = ("level", "severity", "lvl", "log.level", "levelname", "loglevel", "@l")
_MESSAGE_KEYS = ("msg", "message", "event", "@m", "@mt", "text", "log")
_TIME_KEYS = ("time", "timestamp", "ts", "@t", "@timestamp", "datetime", "asctime", "date")
_ERROR_KEYS = ("error", "err", "exception", "exc_info", "stack", "stacktrace")
# Numeric levels: pino/bunyan scale (10..60), and syslog 0..7 is rare in JSON.
_NUMERIC = {10: Severity.DEBUG, 20: Severity.DEBUG, 30: Severity.INFO, 40: Severity.WARNING,
            50: Severity.ERROR, 60: Severity.CRITICAL}
_FATAL_WORDS = {"fatal", "critical", "crit", "panic", "emerg", "emergency", "alert", "dpanic"}


def _get(obj: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in obj:
            return obj[k]
        if "." in k:
            head, tail = k.split(".", 1)
            sub = obj.get(head)
            if isinstance(sub, dict) and tail in sub:
                return sub[tail]
    return None


def _structured(line: str) -> dict[str, Any] | None:
    s = line.strip()
    if not (s.startswith("{") and s.endswith("}")):
        return None
    try:
        obj = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    if _get(obj, _LEVEL_KEYS) is None or _get(obj, _MESSAGE_KEYS) is None:
        return None
    return obj


def _severity(level: Any) -> Severity:
    if isinstance(level, bool):
        return Severity.INFO
    if isinstance(level, int | float):
        return _NUMERIC.get(int(level), Severity.INFO)
    text = str(level).strip().lower()
    if text in _FATAL_WORDS:
        return Severity.CRITICAL
    return level_to_severity(text)


def _timestamp(value: Any) -> datetime | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, int | float):
            secs = value / 1000 if value > 1e11 else value   # epoch ms (pino-like) or s
            return datetime.fromtimestamp(secs, tz=UTC)
        return dateparser.parse(str(value))
    except (ValueError, OverflowError, OSError, TypeError):
        return None


class JsonLinesParser(LogParser):
    FORMAT_NAME = "json"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        lines = [ln for ln in sample_lines[:20] if ln.strip()]
        if not lines:
            return False
        hits = sum(1 for ln in lines if _structured(ln) is not None)
        return hits >= 3 and hits >= 0.6 * len(lines)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        obj = _structured(line)
        if obj is None:
            return None
        level = _get(obj, _LEVEL_KEYS)
        message = str(_get(obj, _MESSAGE_KEYS))
        err = _get(obj, _ERROR_KEYS)
        if err:
            detail = err.get("message", err) if isinstance(err, dict) else err
            message = f"{message}: {detail}"
        source = obj.get("service") or obj.get("logger") or obj.get("name") or "json"
        return ParsedEvent(
            timestamp=_timestamp(_get(obj, _TIME_KEYS)),
            severity=_severity(level),
            source=str(source),
            message=message,
            raw=line,
            line_number=line_number,
            extra={"level": str(level), "app_logger": True},
        )
