class LogcruxError(Exception):
    """Base exception for all logcrux errors."""


class PathValidationError(LogcruxError):
    """Log file path failed security validation."""


class ParseError(LogcruxError):
    """Fatal parser failure (not a per-line skip)."""


class InferenceError(LogcruxError):
    """ONNX model failed to load or run."""


class StateError(LogcruxError):
    """SQLite connection or migration failure."""


class ConfigError(LogcruxError):
    """YAML config is invalid or unreadable."""
