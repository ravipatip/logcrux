from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.hashicorp import HashiCorpParser

_INFO = "2026-06-20T10:23:45.123Z [INFO]  agent: Started Consul agent"
_WARN = "2026-06-20T10:23:47.789Z [WARN]  raft: heartbeat timeout reached, starting election: last-leader="
_ERR = '2026-06-20T10:23:49.345Z [ERROR] core: failed to unseal: error="connection refused"'


@pytest.fixture
def parser():
    return HashiCorpParser()


def test_info(parser):
    e = parser.parse_line(_INFO, 1)
    assert e.severity == Severity.INFO
    assert e.extra["component"] == "agent"
    assert e.timestamp is not None


def test_warn(parser):
    assert parser.parse_line(_WARN, 1).severity == Severity.WARNING


def test_error(parser):
    e = parser.parse_line(_ERR, 1)
    assert e.severity == Severity.ERROR
    assert e.source == "core"


def test_can_parse_by_content():
    assert HashiCorpParser.can_parse(None, [_INFO])
    # an unknown component must not be claimed (avoid poaching other ISO logs)
    assert not HashiCorpParser.can_parse(
        None, ["2026-06-20T10:23:45.123Z [INFO]  myapp: hello"]
    )


def test_can_parse_by_path():
    assert HashiCorpParser.can_parse(Path("/var/log/vault/vault.log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
