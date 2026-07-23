from __future__ import annotations

from pathlib import Path

import numpy as np
from onnxruntime import InferenceSession, SessionOptions
from tokenizers import Tokenizer

from logcrux.models import ParsedEvent

_COSINE_THRESHOLD = 0.75

# Cap on texts embedded per ONNX call so a huge signal set can't build an
# enormous (n, seq_len) tensor in one go.
_EMBED_BATCH = 64


def _mean_pool(token_embeddings: np.ndarray, attention_mask: np.ndarray) -> np.ndarray:
    mask = attention_mask[:, :, np.newaxis].astype(np.float32)
    summed = (token_embeddings * mask).sum(axis=1)
    counts = mask.sum(axis=1).clip(min=1e-9)
    pooled = summed / counts
    norm = np.linalg.norm(pooled, axis=1, keepdims=True).clip(min=1e-9)
    normalized: np.ndarray = pooled / norm
    return normalized


class EventGrouper:
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
        self._tokenizer.enable_truncation(max_length=128)
        # Pad to the longest message in each batch rather than a fixed 128 —
        # typical log lines are ~30 tokens, so fixed-length padding wasted
        # most of the forward pass on [PAD] positions.
        self._tokenizer.enable_padding(pad_id=0, pad_token="[PAD]")

    def _embed_batch(self, texts: list[str]) -> np.ndarray:
        """Embed texts in one (or a few) ONNX calls; returns (n, dim) unit vectors."""
        chunks: list[np.ndarray] = []
        for start in range(0, len(texts), _EMBED_BATCH):
            batch = texts[start : start + _EMBED_BATCH]
            # Truncation keeps 128 tokens (~800 chars); pre-slicing spares the
            # tokenizer from walking a pathologically long message.
            encs = self._tokenizer.encode_batch([t[:1000] for t in batch])
            ids = np.array([e.ids for e in encs], dtype=np.int64)
            mask = np.array([e.attention_mask for e in encs], dtype=np.int64)
            token_type = np.zeros_like(ids)
            out = self._session.run(
                None,
                {"input_ids": ids, "attention_mask": mask, "token_type_ids": token_type},
            )
            chunks.append(_mean_pool(out[0], mask))
        return np.concatenate(chunks, axis=0)

    def _embed(self, text: str) -> np.ndarray:
        embedding: np.ndarray = self._embed_batch([text])[0]
        return embedding

    def group(self, events: list[ParsedEvent]) -> list[list[int]]:
        if not events:
            return []
        # Identical messages (repeated errors are the norm in a burst) share
        # one embedding instead of paying a forward pass each.
        texts = [e.message[:256] for e in events]
        unique: dict[str, int] = {}
        for t in texts:
            if t not in unique:
                unique[t] = len(unique)
        unique_embeddings = self._embed_batch(list(unique))
        embeddings = unique_embeddings[[unique[t] for t in texts]]

        # Cosine similarity of unit vectors = dot product; one matmul replaces
        # the O(n^2) Python loop of per-pair dots.
        sims = embeddings @ embeddings.T
        assigned = [-1] * len(events)
        cluster_id = 0
        for i in range(len(events)):
            if assigned[i] != -1:
                continue
            assigned[i] = cluster_id
            for j in range(i + 1, len(events)):
                if assigned[j] == -1 and sims[i, j] >= _COSINE_THRESHOLD:
                    assigned[j] = cluster_id
            cluster_id += 1
        clusters: dict[int, list[int]] = {}
        for idx, cid in enumerate(assigned):
            clusters.setdefault(cid, []).append(idx)
        return list(clusters.values())
