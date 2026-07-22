from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from logcrux.exceptions import ConfigError


class _StrictModel(BaseModel):
    # Reject unknown keys so a typo (`inferrence:`) fails loudly instead of
    # silently leaving the default in place.
    model_config = ConfigDict(extra="forbid")


class AnalysisConfig(_StrictModel):
    window_size_minutes: int = Field(default=5, ge=1)
    burst_multiplier: float = Field(default=3.0, gt=0)
    auth_failure_threshold: int = Field(default=10, ge=1)
    correlation_gap_seconds: int = Field(default=120, ge=0)
    spike_factor: float = Field(default=3.0, gt=0)


class InferenceConfig(_StrictModel):
    # Softmax confidence over 7 incident classes. The fine-tuned classifier is
    # well-calibrated but the probability mass spreads across semantically
    # overlapping classes (disk_full/oom, network_issue/http_overload), so
    # correct minority-class predictions land around 0.30-0.40. A 0.6 default
    # would suppress almost every categorization; 0.35 surfaces them while still
    # filtering near-random (1/7 ≈ 0.14) guesses.
    threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    enabled: bool = True


class StateConfig(_StrictModel):
    db_path: str = "~/.local/share/logcrux/state.db"
    baseline_alpha: float = Field(default=0.2, gt=0.0, le=1.0)


class SecurityConfig(_StrictModel):
    # Empty = no path restriction: any file the user can read may be analyzed.
    # Set explicit prefixes (e.g. ["/var/log/"]) to sandbox file access.
    allowed_log_paths: list[str] = []
    max_file_size_mb: int = Field(default=2048, ge=1)


class OutputConfig(_StrictModel):
    color: bool = True
    show_remediation: bool = True


class LogcruxConfig(_StrictModel):
    analysis: AnalysisConfig = AnalysisConfig()
    inference: InferenceConfig = InferenceConfig()
    state: StateConfig = StateConfig()
    security: SecurityConfig = SecurityConfig()
    output: OutputConfig = OutputConfig()


def load_config(path: Path | None) -> LogcruxConfig:
    if path is None:
        return LogcruxConfig()
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text())
    except Exception as exc:
        raise ConfigError(f"Cannot parse config {path}: {exc}") from exc
    if raw is None:
        # An empty config file means "all defaults", not an error.
        return LogcruxConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"Config must be a YAML mapping, got {type(raw).__name__}")
    try:
        return LogcruxConfig.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}"
            for err in exc.errors()
        )
        raise ConfigError(f"Invalid config {path}: {problems}") from exc


def resolve_config_path(explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit
    candidates = [
        Path.home() / ".config" / "logcrux" / "logcrux.yaml",
        Path("/etc/logcrux/logcrux.yaml"),
    ]
    for p in candidates:
        if p.exists():
            return p
    return None
