from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from logcrux.inference.classifier import IncidentClassifier
from logcrux.models import AnomalySignal, IncidentCategory, ParsedEvent, Severity, TimeWindow


def _signal(kind: str = "auth_failure_cluster") -> AnomalySignal:
    ts = datetime(2026, 6, 16, 3, 41, 0, tzinfo=UTC)
    return AnomalySignal(
        kind=kind,  # type: ignore[arg-type]
        window=TimeWindow(start=ts, end=ts, duration_seconds=0),
        event_count=60, baseline_count=None,
        severity=Severity.WARNING,
        representative_events=[
            ParsedEvent(
                timestamp=ts, severity=Severity.WARNING, source="sshd",
                message="Failed password for root from 198.51.100.42 port 54001 ssh2",
                raw="raw", line_number=1,
            )
        ],
    )


# Matches the id2label table written to the fine-tuned classifier's config.json
_ID2LABEL = {
    "0": "auth_brute_force",
    "1": "config_error",
    "2": "disk_full",
    "3": "http_overload",
    "4": "network_issue",
    "5": "oom",
    "6": "service_crash",
}


@pytest.fixture
def mock_classifier(tmp_path):
    import json

    model_dir = tmp_path / "classifier"
    model_dir.mkdir()
    (model_dir / "model.onnx").write_bytes(b"fake")
    (model_dir / "config.json").write_text(json.dumps({"id2label": _ID2LABEL}))
    tokenizer_dir = tmp_path / "tokenizer"
    tokenizer_dir.mkdir()

    with patch("logcrux.inference.classifier.InferenceSession") as mock_cls, \
         patch("logcrux.inference.classifier.Tokenizer") as mock_tok_cls:

        mock_session = MagicMock()
        mock_cls.return_value = mock_session
        mock_tok = MagicMock()
        enc = MagicMock()
        enc.ids = [101, 100, 102]
        enc.attention_mask = [1, 1, 1]
        mock_tok.encode.return_value = enc
        mock_tok_cls.from_file.return_value = mock_tok

        clf = IncidentClassifier(model_dir, tokenizer_dir)
        clf._session = mock_session
        clf._tokenizer = mock_tok
        yield clf, mock_session


def test_classify_returns_highest_scoring_category(mock_classifier):
    clf, mock_session = mock_classifier

    # 7-class logits; index 0 (auth_brute_force) dominates after softmax.
    logits = np.array([[8.0, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1]], dtype=np.float32)
    mock_session.run.return_value = [logits]

    result = clf.classify([_signal("auth_failure_cluster")], [[0]], threshold=0.5)
    assert result.category == IncidentCategory.AUTH_BRUTE_FORCE
    # With logit 8.0 for class 0 vs 0.1 for all others, softmax ≈ 0.998
    assert result.confidence > 0.98
    assert result.correlated_signals == ["auth_failure_cluster"]


def test_classify_unknown_when_below_threshold(mock_classifier):
    clf, mock_session = mock_classifier
    # Near-uniform logits → max softmax prob ≈ 1/7, below a 0.99 threshold.
    logits = np.array([[0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1]], dtype=np.float32)
    mock_session.run.return_value = [logits]
    result = clf.classify([_signal()], [[0]], threshold=0.99)
    assert result.category == IncidentCategory.UNKNOWN
    # _inference_usable in the summarizer checks confidence > 0, so UNKNOWN
    # results must carry confidence=0.0 to be correctly rejected downstream.
    assert result.confidence == 0.0
