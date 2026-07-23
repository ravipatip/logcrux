from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from logcrux.inference.grouper import EventGrouper
from logcrux.models import ParsedEvent, Severity


def _ev(msg: str) -> ParsedEvent:
    return ParsedEvent(
        timestamp=datetime.now(UTC), severity=Severity.ERROR,
        source="test", message=msg, raw=msg, line_number=1,
    )


@pytest.fixture
def mock_grouper(tmp_path):
    model_dir = tmp_path / "grouper"
    model_dir.mkdir()
    (model_dir / "model.onnx").write_bytes(b"fake")
    tokenizer_dir = tmp_path / "tokenizer"
    tokenizer_dir.mkdir()

    with patch("logcrux.inference.grouper.InferenceSession") as mock_session_cls, \
         patch("logcrux.inference.grouper.Tokenizer") as mock_tokenizer_cls:

        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_tokenizer = MagicMock()
        mock_tokenizer_cls.from_file.return_value = mock_tokenizer

        grouper = EventGrouper(model_dir, tokenizer_dir)
        grouper._session = mock_session
        grouper._tokenizer = mock_tokenizer
        yield grouper, mock_session, mock_tokenizer


def test_group_similar_messages(mock_grouper):
    grouper, mock_session, mock_tokenizer = mock_grouper

    def encode_batch(texts):
        encs = []
        for _ in texts:
            enc = MagicMock()
            enc.ids = [101, 100, 102]
            enc.attention_mask = [1, 1, 1]
            encs.append(enc)
        return encs

    mock_tokenizer.encode_batch.side_effect = encode_batch

    def run(output_names, inputs):
        # One token-embedding row per input; every token in a message carries
        # the same vector, so mean-pooling yields that vector normalized.
        # Messages 0 and 1 → [1,0,0]; message 2 → [0,1,0].
        vectors = [[1.0, 0.0, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]]
        batch = len(inputs["input_ids"])
        hidden = np.array(
            [[vectors[i]] * 3 for i in range(batch)], dtype=np.float32
        )
        return [hidden]

    mock_session.run.side_effect = run

    events = [_ev("OOM killer fired"), _ev("OOM process killed"), _ev("SSH login failed")]
    clusters = grouper.group(events)
    # Events 0 and 1 share embedding [1,0,0]; event 2 gets [0,1,0].
    # Cosine([1,0,0],[0,1,0]) = 0.0 < 0.75 threshold → two separate clusters.
    assert len(clusters) == 2
    oom_cluster = next(c for c in clusters if 0 in c)
    assert 1 in oom_cluster      # OOM events co-clustered
    assert 2 not in oom_cluster  # SSH event is in a separate cluster


def test_group_empty_events(mock_grouper):
    grouper, _, _ = mock_grouper
    assert grouper.group([]) == []
