from __future__ import annotations

import importlib.resources
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from logcrux.exceptions import InferenceError
from logcrux.models import AnalysisResult, InferenceResult, ParsedEvent

if TYPE_CHECKING:
    from logcrux.inference.classifier import IncidentClassifier
    from logcrux.inference.grouper import EventGrouper

logger = logging.getLogger(__name__)
# Said once per process, not once per file of a directory run.
_warned = False


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
            global _warned
            if not _warned:
                _warned = True
                hint = ""
                if isinstance(exc.__cause__, ImportError) or isinstance(exc, ImportError):
                    hint = (" onnxruntime is not installed (it has no wheel for this Python"
                            " or platform); detection is unaffected, only incident naming"
                            " is. For it: `uv tool install --python 3.12 logcrux`.")
                logger.warning("AI classification unavailable: %s.%s", exc, hint)
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
            # Imported here, not at module load: onnxruntime is optional
            # (no wheel for Python 3.15 or musl), and logcrux must still run.
            from logcrux.inference.classifier import IncidentClassifier
            from logcrux.inference.grouper import EventGrouper

            tokenizer_dir = _bundled_path("tokenizer")
            self._grouper = EventGrouper(_bundled_path("grouper"), tokenizer_dir)
            self._classifier = IncidentClassifier(_bundled_path("classifier"), tokenizer_dir)
        except Exception as exc:
            raise InferenceError(f"Failed to load ONNX models: {exc}") from exc
