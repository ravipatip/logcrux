from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from onnxruntime import InferenceSession, SessionOptions
from tokenizers import Tokenizer

from logcrux.models import AnomalySignal, IncidentCategory, InferenceResult


def _softmax(x: np.ndarray) -> np.ndarray:
    """Row-wise softmax for 1-D or 2-D logits."""
    e = np.exp(x - np.max(x, axis=-1, keepdims=True))
    return np.asarray(e / e.sum(axis=-1, keepdims=True), dtype=np.float32)


class IncidentClassifier:
    """Single-label incident classifier.

    The bundled ONNX model is a fine-tuned 7-way sequence classifier
    (``AutoModelForSequenceClassification``). We tokenise the incident text
    once, run a single forward pass, softmax the logits, and map the argmax
    back to an :class:`IncidentCategory` via the ``id2label`` table saved in
    the model's ``config.json``.
    """

    def __init__(self, model_dir: Path, tokenizer_dir: Path) -> None:
        opts = SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 2
        self._session = InferenceSession(
            str(model_dir / "model.onnx"),
            sess_options=opts,
            providers=["CPUExecutionProvider"],
        )
        self._tokenizer = Tokenizer.from_file(str(tokenizer_dir / "tokenizer.json"))
        self._tokenizer.enable_truncation(max_length=256)
        # No fixed length: pad each batch to its longest member. Log lines are
        # typically ~30 tokens, so always padding to 256 cost ~8x the compute
        # of the tokens that actually carry signal.
        self._tokenizer.enable_padding(pad_id=0, pad_token="[PAD]")
        self._id2label = self._load_id2label(model_dir)

    @staticmethod
    def _load_id2label(model_dir: Path) -> dict[int, IncidentCategory]:
        """Map model output indices to IncidentCategory using config.json."""
        config_path = model_dir / "config.json"
        mapping: dict[int, IncidentCategory] = {}
        if config_path.exists():
            cfg = json.loads(config_path.read_text())
            for idx, label in cfg.get("id2label", {}).items():
                try:
                    mapping[int(idx)] = IncidentCategory(label)
                except ValueError:
                    continue
        return mapping

    def _predict_batch(self, texts: list[str]) -> np.ndarray:
        """One forward pass over all texts; returns (n, n_labels) logits."""
        # Truncation keeps only the first 256 tokens (~1500 chars), but the
        # tokenizer still walks the whole string first — a multi-KB message
        # (dumped payload, minified JSON) costs seconds for zero extra signal.
        encs = self._tokenizer.encode_batch([t[:2000] for t in texts])
        ids = np.array([e.ids for e in encs], dtype=np.int64)
        mask = np.array([e.attention_mask for e in encs], dtype=np.int64)
        token_type = np.zeros_like(ids)
        out = self._session.run(
            None,
            {"input_ids": ids, "attention_mask": mask, "token_type_ids": token_type},
        )
        return np.asarray(out[0], dtype=np.float32)

    def _predict(self, text: str) -> np.ndarray:
        logits: np.ndarray = self._predict_batch([text])[0]
        return logits

    def classify(
        self,
        signals: list[AnomalySignal],
        clusters: list[list[int]],
        threshold: float = 0.6,
    ) -> InferenceResult:
        # The model is trained on single log messages, so we classify each
        # representative message independently and average the softmax
        # distributions. This avoids the train/inference mismatch of feeding
        # one long concatenated string and is robust to a few off-topic lines.
        messages: list[str] = []
        seen: set[str] = set()
        for signal in signals:
            for ev in signal.representative_events[:8]:
                msg = ev.message[:256].strip()
                if msg and msg not in seen:
                    seen.add(msg)
                    messages.append(msg)
        messages = messages[:30]

        if not messages:
            return InferenceResult(
                category=IncidentCategory.UNKNOWN,
                confidence=0.0,
                correlated_signals=[s.kind for s in signals],
                grouped_event_clusters=clusters,
            )

        probs = _softmax(self._predict_batch(messages)).mean(axis=0)

        best_idx = int(np.argmax(probs))
        best_score = float(probs[best_idx])
        best_category = self._id2label.get(best_idx, IncidentCategory.UNKNOWN)

        if best_score < threshold:
            best_category = IncidentCategory.UNKNOWN
            best_score = 0.0

        return InferenceResult(
            category=best_category,
            confidence=best_score,
            correlated_signals=[s.kind for s in signals],
            grouped_event_clusters=clusters,
        )
