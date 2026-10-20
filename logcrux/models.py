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

    def model_post_init(self, __context: Any) -> None:
        # pydantic keeps a per-instance set of which fields were passed — 728
        # bytes on CPython 3.12, more than the event's own data. One event per
        # log line made it ~35% of peak RSS on a real 510k-line access log.
        # Nothing here uses exclude_unset, and every field always has a value,
        # so one shared set holding all names answers every query identically
        # (pydantic only ever .add()s to it, a no-op for a name already there).
        object.__setattr__(self, "__pydantic_fields_set__", _EVENT_FIELDS)


_EVENT_FIELDS: set[str] = set(ParsedEvent.model_fields)


class TimeWindow(BaseModel):
    start: datetime
    end: datetime
    duration_seconds: float


class Subject(BaseModel):
    """Something a finding is about: a source IP, a user, a unit, a process,
    an HTTP status, or a recurring message template — with how often it
    occurred among the events the detector matched."""
    label: str
    value: str
    count: int


class EvidenceLine(BaseModel):
    line: int
    timestamp: datetime | None = None
    source: str | None = None
    # ``text`` is the line verbatim (grep for it); ``message`` is the parsed
    # message without the timestamp/host prefix — what the terminal shows.
    text: str
    message: str | None = None


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
        "job_failure",
        "policy_denial",
        "storage_fault",
        "config_error",
        "backend_down",
        "uncaught_exception",
        "resource_limit",
        "tls_error",
        "mail_reject_cluster",
        "fatal_exit",
        "clock_jump",
        "probe_failure",
        "unknown",
    ]
    window: TimeWindow
    event_count: int
    baseline_count: float | None
    severity: Severity
    representative_events: list[ParsedEvent]
    subjects: list[Subject] = Field(default_factory=list)
    # The lines shown as proof, chosen over every matched event (see
    # analysis.evidence.evidence_events); empty means use the sample.
    evidence: list[ParsedEvent] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    log_path: str
    parser_format: str
    parsed_count: int
    skipped_count: int
    time_range: TimeWindow | None
    signals: list[AnomalySignal]
    severity_counts: dict[str, int] = Field(default_factory=dict)
    last_error: ParsedEvent | None = None


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
    kind: str | None = None
    count: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    subjects: list[Subject] = Field(default_factory=list)
    evidence: list[EvidenceLine] = Field(default_factory=list)


# Bumped when the JSON shape changes. 2: findings carry kind, count,
# first/last seen, subjects and evidence lines; the summary carries what was
# checked (time_range, severity_counts, coverage).
SCHEMA_VERSION = "2"


class Coverage(BaseModel):
    lines: int
    parsed: int
    unparsed: int
    ratio: float


class IncidentSummary(BaseModel):
    schema_version: str = SCHEMA_VERSION
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
    time_range: TimeWindow | None = None
    severity_counts: dict[str, int] = Field(default_factory=dict)
    coverage: Coverage | None = None
    warnings: list[str] = Field(default_factory=list)
    # Every signal raised; ``findings`` lists at most the first five.
    signal_count: int = 0
    # On a CLEAN result for a short log: the error it stops on, if any — the
    # likely reason a container or job exited, but too little to alarm on.
    last_error: EvidenceLine | None = None
