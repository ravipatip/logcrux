from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# OTLP (OpenTelemetry Protocol) JSON log records — the vendor-neutral log format
# emitted by the OpenTelemetry Collector's file/otlpjson exporters and the
# baseline instrumentation standard across modern cloud-native stacks. One JSON
# record per line, e.g.:
#   {"timeUnixNano":"1718000014000000000","severityNumber":17,
#    "severityText":"ERROR","body":{"stringValue":"connect failed"},
#    "traceId":"abc","resource":{"service.name":"checkout"}}
# The `severityNumber` is OTel's normalized 1-24 scale (TRACE 1-4, DEBUG 5-8,
# INFO 9-12, WARN 13-16, ERROR 17-20, FATAL 21-24); we map it to our Severity.
# Without this parser these records fall to generic, which loses the nanosecond
# timestamp and shows the raw JSON blob instead of the human `body`.


def _severity_from_number(num: int) -> Severity:
    if num >= 21:
        return Severity.CRITICAL
    if num >= 17:
        return Severity.ERROR
    if num >= 13:
        return Severity.WARNING
    if num >= 9:
        return Severity.INFO
    return Severity.DEBUG  # 1-8: TRACE/DEBUG


_TEXT_SEVERITY = {
    "trace": Severity.DEBUG,
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "err": Severity.ERROR,
    "fatal": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
}


def _get(obj: dict[str, object], *keys: str) -> object:
    """First present key (handles OTLP/JSON camelCase and snake_case variants)."""
    for k in keys:
        if k in obj:
            return obj[k]
    return None


def _is_otlp(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and ("body" in obj)
        and (
            "severityNumber" in obj
            or "severity_number" in obj
            or "severityText" in obj
            or "severity_text" in obj
        )
    )


def _extract_body(body: object) -> str:
    # OTLP `body` is an AnyValue: usually {"stringValue": "..."} in JSON, but some
    # exporters emit a bare string or a structured kvlist/array value.
    if isinstance(body, str):
        return body
    if isinstance(body, dict):
        for key in ("stringValue", "string_value"):
            val = body.get(key)
            if isinstance(val, str):
                return val
        return json.dumps(body, separators=(",", ":"))
    return str(body)


def _parse_unix_nano(value: object) -> datetime | None:
    if not isinstance(value, (int, float, str)):
        return None
    try:
        ns = int(value)
    except (TypeError, ValueError):
        return None
    if ns <= 0:
        return None
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc)


class OTLPParser(LogParser):
    FORMAT_NAME = "otlp"

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
            if _is_otlp(obj):
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
        if not _is_otlp(obj):
            return None

        num = _get(obj, "severityNumber", "severity_number")
        text = _get(obj, "severityText", "severity_text")
        if isinstance(num, int):
            severity = _severity_from_number(num)
        elif isinstance(text, str):
            severity = _TEXT_SEVERITY.get(text.lower(), Severity.INFO)
        else:
            severity = Severity.INFO

        ts = _parse_unix_nano(
            _get(obj, "timeUnixNano", "time_unix_nano",
                 "observedTimeUnixNano", "observed_time_unix_nano")
        )

        message = _extract_body(obj["body"])
        extra: dict[str, str] = {}
        trace = _get(obj, "traceId", "trace_id")
        if isinstance(trace, str) and trace:
            extra["trace_id"] = trace
        resource = obj.get("resource")
        if isinstance(resource, dict):
            svc = resource.get("service.name") or resource.get("service_name")
            if isinstance(svc, str):
                extra["service"] = svc

        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source=extra.get("service", "otlp"),
            message=message or "(empty)",
            raw=line,
            line_number=line_number,
            extra=extra,
        )
