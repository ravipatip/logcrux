from datetime import UTC, datetime

from logcrux.models import (
    AnalysisResult,
    IncidentCategory,
    IncidentSummary,
    InferenceResult,
    ParsedEvent,
    Severity,
)


def test_parsed_event_defaults():
    e = ParsedEvent(
        timestamp=None,
        severity=Severity.ERROR,
        source="kernel",
        message="OOM killer fired",
        raw="Jun 16 03:42:15 host kernel: OOM killer fired",
        line_number=1,
    )
    assert e.extra == {}
    assert e.severity == Severity.ERROR


def test_analysis_result_empty_signals():
    result = AnalysisResult(
        log_path="/var/log/messages",
        parser_format="syslog",
        parsed_count=100,
        skipped_count=2,
        time_range=None,
        signals=[],
    )
    assert result.signals == []


def test_incident_summary_has_uuid_analysis_id():
    s = IncidentSummary(
        level="CLEAN",
        title="No incidents",
        findings=[],
        confidence=1.0,
        category=IncidentCategory.UNKNOWN,
        log_path="/var/log/messages",
        analyzed_at=datetime.now(UTC),
        parsed_count=0,
        elapsed_seconds=0.1,
    )
    assert len(s.analysis_id) == 36


def test_inference_result_confidence_stored():
    # InferenceResult has no range validator — verify confidence is stored as-is.
    r_low = InferenceResult(
        category=IncidentCategory.OOM,
        confidence=0.0,
        correlated_signals=[],
        grouped_event_clusters=[],
    )
    assert r_low.confidence == 0.0
    r_high = InferenceResult(
        category=IncidentCategory.UNKNOWN,
        confidence=1.0,
        correlated_signals=[],
        grouped_event_clusters=[],
    )
    assert r_high.confidence == 1.0
