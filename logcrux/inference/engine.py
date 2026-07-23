from __future__ import annotations

import importlib.resources
import logging
from pathlib import Path

from logcrux.exceptions import InferenceError
from logcrux.inference.classifier import IncidentClassifier
from logcrux.inference.grouper import EventGrouper
from logcrux.models import AnalysisResult, InferenceResult, ParsedEvent

logger = logging.getLogger(__name__)


def _bundled_path(subpath: str) -> Path:
    ref = importlib.resources.files("logcrux.inference.models").joinpath(subpath)
    with importlib.resources.as_file(ref) as p:
        return Path(p)


class InferenceEngine:
    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._classifier: IncidentClassifier | None = None
        self._grouper: EventGrouper | None = None

    def run(
        self,
        result: AnalysisResult,
        threshold: float = 0.6,
    ) -> InferenceResult | None:
        if not self._enabled or not result.signals:
            return None
        try:
            self._ensure_loaded()
        except Exception as exc:
            logger.warning(
                "AI inference unavailable: %s. Showing statistical findings only.", exc
            )
            return None
        assert self._grouper is not None
        assert self._classifier is not None

        all_events: list[ParsedEvent] = []
        for signal in result.signals:
            all_events.extend(signal.representative_events)

        clusters = self._grouper.group(all_events)
        return self._classifier.classify(result.signals, clusters, threshold=threshold)

    def _ensure_loaded(self) -> None:
        if self._classifier is not None:
            return
        try:
            tokenizer_dir = _bundled_path("tokenizer")
            self._grouper = EventGrouper(_bundled_path("grouper"), tokenizer_dir)
            self._classifier = IncidentClassifier(_bundled_path("classifier"), tokenizer_dir)
        except Exception as exc:
            raise InferenceError(f"Failed to load ONNX models: {exc}") from exc
