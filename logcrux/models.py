from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


def event_time_bounds(
    events: Iterable[ParsedEvent],
) -> tuple[datetime, datetime] | None:
    """Return (earliest, latest) timestamp across events that carry one.

    Returns None when no event has a timestamp. Centralizing the None-filter
    here keeps the type checker happy (callers get concrete ``datetime``s) and
    avoids the repeated ``# type: ignore`` dance around ``min``/``max``.
    """
    times = [e.timestamp for e in events if e.timestamp is not None]
    if not times:
        return None
    return min(times), max(times)


def event_sort_key(event: ParsedEvent) -> datetime:
    """Sort/compare key for events the caller has filtered to non-None
    timestamps. Falls back to ``datetime.min`` so the type stays concrete
    (no ``datetime | None``); the fallback never triggers for filtered input.
    """
    return event.timestamp or datetime.min


class Severity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ParsedEvent(BaseModel):
    timestamp: datetime | None
    severity: Severity
    source: str
    message: str
    raw: str
    line_number: int
    extra: dict[str, Any] = Field(default_factory=dict)


class TimeWindow(BaseModel):
    start: datetime
    end: datetime
    duration_seconds: float


class AnomalySignal(BaseModel):
    kind: Literal[
        "error_burst",
        "rate_spike",
        "auth_failure_cluster",
        "oom_event",
        "service_crash",
        "disk_full",
        "tunnel_anomaly",
        "proxy_denial_cluster",
        "firewall_block_cluster",
        "unknown",
    ]
    window: TimeWindow
    event_count: int
    baseline_count: float | None
    severity: Severity
    representative_events: list[ParsedEvent]


class AnalysisResult(BaseModel):
    log_path: str
    parser_format: str
    parsed_count: int
    skipped_count: int
    time_range: TimeWindow | None
    signals: list[AnomalySignal]


class IncidentCategory(str, Enum):
    OOM = "oom"
    AUTH_BRUTE_FORCE = "auth_brute_force"
    HTTP_OVERLOAD = "http_overload"
    DISK_FULL = "disk_full"
    SERVICE_CRASH = "service_crash"
    CONFIG_ERROR = "config_error"
    NETWORK_ISSUE = "network_issue"
    UNKNOWN = "unknown"


class InferenceResult(BaseModel):
    category: IncidentCategory
    confidence: float
    correlated_signals: list[str]
    grouped_event_clusters: list[list[int]]


class Finding(BaseModel):
    headline: str
    detail: str | None = None


class IncidentSummary(BaseModel):
    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    level: Literal["CRITICAL", "WARNING", "INFO", "CLEAN"]
    title: str
    findings: list[Finding]
    confidence: float
    category: IncidentCategory
    remediation: str | None = None
    log_path: str
    parser_format: str = "unknown"
    analyzed_at: datetime
    parsed_count: int
    skipped_count: int = 0
    elapsed_seconds: float
