from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.cri import CRIParser
from logcrux.parsers.docker import DockerParser
from logcrux.parsers.registry import detect_parser


@pytest.fixture
def parser():
    return CRIParser()


_INFO = "2026-06-29T08:40:14.123456789Z stdout F Starting application server on :8080"
_ERR = (
    "2026-06-29T08:41:02.551239871Z stderr F ERROR could not connect to upstream "
    "payment-svc: connection refused"
)
_PARTIAL = '2026-06-29T08:41:03.100000000Z stderr P Exception in thread "main"'
_STDERR_PLAIN = "2026-06-29T08:41:05.000000000Z stderr F shutting down workers"
_OFFSET_TZ = "2026-06-29T08:40:14.123456789+02:00 stdout F ready"


def test_parse_stdout_info(parser):
    event = parser.parse_line(_INFO, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "cri"
    assert event.extra["stream"] == "stdout"
    assert event.extra["partial"] is False
    assert event.timestamp is not None
    assert event.message == "Starting application server on :8080"


def test_parse_error_keyword(parser):
    event = parser.parse_line(_ERR, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.timestamp is not None


def test_partial_tag_flagged(parser):
    event = parser.parse_line(_PARTIAL, 1)
    assert event is not None
    assert event.extra["partial"] is True


def test_bare_stderr_is_at_least_warning(parser):
    event = parser.parse_line(_STDERR_PLAIN, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_timezone_offset_timestamp(parser):
    event = parser.parse_line(_OFFSET_TZ, 1)
    assert event is not None
    assert event.timestamp is not None


def test_non_cri_returns_none(parser):
    assert parser.parse_line("plain text log line", 1) is None
    assert parser.parse_line('{"log":"x","stream":"stdout","time":"t"}', 1) is None
    assert parser.parse_line("", 1) is None


def test_can_parse_by_content():
    assert CRIParser.can_parse(None, [_INFO, _ERR])


def test_can_parse_by_containers_path():
    sample = [_INFO]
    assert CRIParser.can_parse(
        Path("/var/log/containers/app_default_abc123.log"), sample
    )


def test_detect_cri_from_stream():
    """A piped `crictl logs` stream (no path) is detected as CRI, not generic."""
    parser = detect_parser(None, [_INFO, _ERR, _STDERR_PLAIN])
    assert isinstance(parser, CRIParser)


def test_docker_json_not_misdetected_as_cri():
    """The legacy Docker json-file shape must not be claimed by CRI."""
    docker_line = (
        '{"log":"hello\\n","stream":"stdout","time":"2026-06-29T08:40:14.1Z"}'
    )
    assert not CRIParser.can_parse(None, [docker_line])
    parser = detect_parser(None, [docker_line])
    assert isinstance(parser, DockerParser)
