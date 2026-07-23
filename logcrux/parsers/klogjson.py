from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# klog structured JSON (`--logging-format=json`) — emitted by Kubernetes core
# components (kube-apiserver, kubelet, scheduler, controller-manager) and most
# controllers/operators (cert-manager, external-dns, ArgoCD, etc.) when JSON
# logging is enabled. Schema (k8s.io/klog/v2):
#   InfoS:  {"ts":1718000014.047,"caller":"server.go:120","msg":"Starting","v":0,...}
#   ErrorS: {"ts":1718000062.551,"caller":"sync.go:88","msg":"Reconciler error",
#            "err":"connection refused",...}
# Distinct from the etcd/otel zap encoders, which carry a "level" field and a
# string RFC3339 "ts"; klog uses a numeric epoch "ts" plus "v" (verbosity) and/or
# "err", and never a "level". Without this parser these records fall to generic,
# which loses the timestamp and shows the raw JSON blob instead of "msg".


def _is_klog_json(obj: object) -> bool:
    return (
        isinstance(obj, dict)
        and "msg" in obj
        and "caller" in obj
        and "ts" in obj
        and "level" not in obj  # a "level" field means zap (etcd/otel), not klog
        and ("v" in obj or "err" in obj or "error" in obj)
    )


def _parse_ts(value: object) -> datetime | None:
    # klog defaults to a float epoch-seconds "ts"; some setups emit RFC3339.
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    if isinstance(value, str):
        try:
            return dateparser.parse(value)
        except (ValueError, OverflowError):
            return None
    return None


class KlogJsonParser(LogParser):
    FORMAT_NAME = "klog-json"

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
            if _is_klog_json(obj):
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
        if not _is_klog_json(obj):
            return None

        err = obj.get("err") or obj.get("error")
        severity = Severity.ERROR if err else Severity.INFO
        message = str(obj.get("msg", "")).strip()
        if err:
            message = f"{message}: {err}"

        extra: dict[str, str] = {"caller": str(obj["caller"])}
        if "v" in obj:
            extra["v"] = str(obj["v"])

        return ParsedEvent(
            timestamp=_parse_ts(obj.get("ts")),
            severity=severity,
            source="klog",
            message=message or "(empty)",
            raw=line,
            line_number=line_number,
            extra=extra,
        )
