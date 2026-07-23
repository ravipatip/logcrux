from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# The OpenTelemetry Collector logs with zap (the same encoder etcd uses), but
# its entries carry a pipeline-component ``kind`` and component name, e.g.:
#   {"level":"info","ts":"2026-06-23T10:23:45.123Z","caller":"service/service.go:1",
#    "msg":"Everything is ready","kind":"exporter","name":"otlp"}
#   {"level":"error","ts":...,"caller":"exporterhelper/queue.go:1",
#    "msg":"Exporting failed","kind":"exporter","name":"otlp","error":"connection refused"}
# The ``kind`` field (receiver/processor/exporter/extension/connector) keys
# detection so it is claimed before the generic etcd zap parser.
_OTEL_KINDS = {"receiver", "processor", "exporter", "extension", "connector", "pipeline"}


def _is_otel(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "msg" in obj
        and "level" in obj
        and str(obj.get("kind", "")).lower() in _OTEL_KINDS
    )


class OtelParser(LogParser):
    FORMAT_NAME = "otel"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        # Detect on otel's actual zap content (a pipeline "kind"), never on the
        # path alone: claiming any "*collector*"/"*otel*" file that merely has a
        # JSON line would mis-route unrelated JSON logs (and otel shares the zap
        # encoder with etcd, so content disambiguation is what matters).
        for line in sample_lines[:10]:
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            if _is_otel(obj):
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
        if not isinstance(obj, dict) or "msg" not in obj:
            return None
        ts: datetime | None = None
        raw_ts = obj.get("ts")
        if isinstance(raw_ts, str):
            try:
                ts = dateparser.parse(raw_ts)
            except (ValueError, TypeError, OverflowError):
                ts = None
        elif isinstance(raw_ts, (int, float)):
            try:
                ts = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                ts = None
        level = str(obj.get("level", "info"))
        message = str(obj.get("msg", ""))
        if obj.get("error"):
            message = f"{message} error={obj['error']}"
        extra: dict[str, object] = {"level": level.lower()}
        for key in ("kind", "name", "caller", "error", "data_type"):
            if key in obj:
                extra[key] = obj[key]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source=f"otelcol/{obj.get('kind', '')}".rstrip("/"),
            message=message.strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
