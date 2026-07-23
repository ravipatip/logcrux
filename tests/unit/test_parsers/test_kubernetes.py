from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.kubernetes import KubernetesParser


@pytest.fixture
def parser():
    return KubernetesParser()


_LINE = '{"log":"Starting server\\n","stream":"stdout","time":"2026-06-19T10:00:01.123456789Z"}'
_ERROR_LINE = '{"log":"ERROR: OOM killed\\n","stream":"stderr","time":"2026-06-19T10:00:02.123456789Z"}'


def test_parse_stdout(parser):
    event = parser.parse_line(_LINE, 1)
    assert event is not None
    assert event.source == "kubernetes"
    assert event.severity == Severity.INFO


def test_parse_error(parser):
    event = parser.parse_line(_ERROR_LINE, 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_can_parse_by_pod_path():
    assert KubernetesParser.can_parse(
        Path("/var/log/pods/default_myapp-6d9f_abc123/app/0.log"), []
    )


def test_cannot_parse_docker_path():
    assert not KubernetesParser.can_parse(
        Path("/var/lib/docker/containers/abc/abc-json.log"), []
    )


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
