from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from logcrux.inference.engine import InferenceEngine
from logcrux.models import (
    AnalysisResult,
    AnomalySignal,
    IncidentCategory,
    InferenceResult,
    Severity,
    TimeWindow,
)


def _empty_result() -> AnalysisResult:
    return AnalysisResult(
        log_path="/var/log/test.log", parser_format="syslog",
        parsed_count=100, skipped_count=0, time_range=None, signals=[],
    )


def _result_with_signal() -> AnalysisResult:
    ts = datetime(2026, 6, 16, 3, 41, 0, tzinfo=UTC)
    return AnalysisResult(
        log_path="/var/log/test.log", parser_format="syslog",
        parsed_count=100, skipped_count=0,
        time_range=TimeWindow(start=ts, end=ts, duration_seconds=0),
        signals=[AnomalySignal(
            kind="auth_failure_cluster",
            window=TimeWindow(start=ts, end=ts, duration_seconds=0),
            event_count=60, baseline_count=None,
            severity=Severity.WARNING, representative_events=[],
        )],
    )


def test_skips_model_load_for_empty_signals():
    engine = InferenceEngine(enabled=True)
    with patch.object(engine, "_ensure_loaded") as mock_load:
        result = engine.run(_empty_result())
    mock_load.assert_not_called()
    assert result is None


def test_returns_none_when_disabled():
    engine = InferenceEngine(enabled=False)
    result = engine.run(_result_with_signal())
    assert result is None


def test_calls_classifier_when_signals_present():
    engine = InferenceEngine(enabled=True)
    mock_clf = MagicMock()
    mock_grouper = MagicMock()
    mock_grouper.group.return_value = [[0]]
    mock_clf.classify.return_value = InferenceResult(
        category=IncidentCategory.AUTH_BRUTE_FORCE,
        confidence=0.96,
        correlated_signals=["auth_failure_cluster"],
        grouped_event_clusters=[[0]],
    )
    engine._classifier = mock_clf
    engine._grouper = mock_grouper

    result = engine.run(_result_with_signal(), threshold=0.6)
    assert result is not None
    assert result.category == IncidentCategory.AUTH_BRUTE_FORCE
    mock_grouper.group.assert_called_once()
    mock_clf.classify.assert_called_once()


def test_inference_error_returns_none_gracefully():
    engine = InferenceEngine(enabled=True)
    with patch.object(engine, "_ensure_loaded", side_effect=Exception("model missing")):
        result = engine.run(_result_with_signal())
    assert result is None
