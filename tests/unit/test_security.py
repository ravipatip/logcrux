from datetime import timedelta

import pytest

from logcrux.config import SecurityConfig
from logcrux.exceptions import PathValidationError
from logcrux.security import parse_duration, validate_log_path


@pytest.fixture
def sec_config(tmp_path):
    return SecurityConfig(
        allowed_log_paths=[str(tmp_path)],
        max_file_size_mb=10,
    )


def test_valid_file_passes(tmp_path, sec_config):
    f = tmp_path / "app.log"
    f.write_text("hello\n")
    result = validate_log_path(str(f), sec_config)
    assert result == f.resolve()


def test_missing_file_raises(tmp_path, sec_config):
    with pytest.raises(PathValidationError, match="not found"):
        validate_log_path(str(tmp_path / "ghost.log"), sec_config)


def test_directory_raises(tmp_path, sec_config):
    with pytest.raises(PathValidationError, match="Not a regular file"):
        validate_log_path(str(tmp_path), sec_config)


def test_outside_allowed_path_raises(tmp_path):
    cfg = SecurityConfig(allowed_log_paths=["/var/log/"], max_file_size_mb=10)
    f = tmp_path / "app.log"
    f.write_text("hello\n")
    with pytest.raises(PathValidationError, match="outside allowed"):
        validate_log_path(str(f), cfg)


def test_empty_allowlist_permits_any_readable_file(tmp_path):
    # Default config has no path restriction: any readable file is allowed.
    cfg = SecurityConfig(allowed_log_paths=[], max_file_size_mb=10)
    assert cfg.allowed_log_paths == []
    f = tmp_path / "anywhere.log"
    f.write_text("hello\n")
    assert validate_log_path(str(f), cfg) == f.resolve()


def test_oversized_file_raises(tmp_path, sec_config):
    f = tmp_path / "big.log"
    f.write_bytes(b"x" * (11 * 1024 * 1024))
    with pytest.raises(PathValidationError, match="exceeds limit"):
        validate_log_path(str(f), sec_config)


@pytest.mark.parametrize("s,expected", [
    ("30s", timedelta(seconds=30)),
    ("10m", timedelta(minutes=10)),
    ("2h", timedelta(hours=2)),
    ("1d", timedelta(days=1)),
])
def test_parse_duration_valid(s, expected):
    assert parse_duration(s) == expected


def test_parse_duration_invalid():
    with pytest.raises(ValueError, match="Invalid duration"):
        parse_duration("2weeks")
