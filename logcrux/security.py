from __future__ import annotations

import os
import re
from datetime import timedelta
from pathlib import Path

from logcrux.config import SecurityConfig
from logcrux.exceptions import PathValidationError


def validate_log_path(raw: str, config: SecurityConfig) -> Path:
    path = Path(raw).resolve()
    if not path.exists():
        raise PathValidationError(f"File not found: {path}")
    if not path.is_file():
        raise PathValidationError(f"Not a regular file: {path}")
    if not os.access(path, os.R_OK):
        raise PathValidationError(f"Permission denied: {path}")
    # An empty whitelist means no path restriction — the user can analyze any
    # file they already have OS read access to (checked above).
    if config.allowed_log_paths:
        allowed = [Path(p).resolve() for p in config.allowed_log_paths]
        if not any(path.is_relative_to(a) for a in allowed):
            raise PathValidationError(
                f"Path {path} is outside allowed directories: {config.allowed_log_paths}"
            )
    size_mb = path.stat().st_size / (1024 * 1024)
    if size_mb > config.max_file_size_mb:
        raise PathValidationError(
            f"File size {size_mb:.0f}MB exceeds limit {config.max_file_size_mb}MB"
        )
    return path


def parse_duration(s: str) -> timedelta:
    match = re.fullmatch(r"(\d+)([smhd])", s)
    if not match:
        raise ValueError(
            f"Invalid duration: {s!r}. Use format: 30s, 10m, 2h, 1d"
        )
    value, unit = int(match.group(1)), match.group(2)
    return {"s": timedelta(seconds=value), "m": timedelta(minutes=value),
            "h": timedelta(hours=value), "d": timedelta(days=value)}[unit]
