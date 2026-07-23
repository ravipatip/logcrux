from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.docker import DockerParser


@pytest.fixture
def parser():
    return DockerParser()


_STDOUT = '{"log":"Starting application server on port 8080\\n","stream":"stdout","time":"2026-06-19T10:00:01.123456789Z"}'
_STDERR_ERR = '{"log":"ERROR: Failed to connect to Redis\\n","stream":"stderr","time":"2026-06-19T10:00:03.345678901Z"}'
_STDOUT_WARN = '{"log":"WARNING: Cache miss rate above 80%\\n","stream":"stdout","time":"2026-06-19T10:00:04.456789012Z"}'
_PANIC = '{"log":"panic: runtime error: index out of range\\n","stream":"stderr","time":"2026-06-19T10:00:05.567890123Z"}'


def test_parse_stdout_info(parser):
    event = parser.parse_line(_STDOUT, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "docker"
    assert event.extra["stream"] == "stdout"
    assert event.timestamp is not None


def test_parse_error_keyword_in_log(parser):
    event = parser.parse_line(_STDERR_ERR, 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_parse_warning_keyword_in_stdout(parser):
    event = parser.parse_line(_STDOUT_WARN, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_parse_panic_is_error(parser):
    event = parser.parse_line(_PANIC, 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_parse_non_json_returns_none(parser):
    assert parser.parse_line("plain text log line", 1) is None


def test_can_parse_by_path():
    assert DockerParser.can_parse(
        Path("/var/lib/docker/containers/abc123/abc123-json.log"), []
    )


def test_can_parse_by_content():
    assert DockerParser.can_parse(None, [_STDOUT])


def test_fixture(parser):
    fixture = Path("tests/fixtures/docker.log")
    with open(fixture) as f:
        events = list(parser.parse_stream(f))
    assert len(events) == 5
    errors = [e for e in events if e.severity == Severity.ERROR]
    assert len(errors) >= 2
