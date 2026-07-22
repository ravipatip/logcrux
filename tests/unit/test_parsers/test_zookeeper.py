from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.zookeeper import ZookeeperParser

_INFO = "2026-06-20 10:23:45,123 [myid:1] - INFO  [main:QuorumPeerMain@123] - Starting quorum peer"
_WARN = "2026-06-20 10:23:47,789 [myid:1] - WARN  [SyncThread:0:SyncRequestProcessor@189] - Too busy to snap"
_ERR = "2026-06-20 10:23:48,012 [myid:1] - ERROR [main:QuorumPeer@1234] - Unexpected exception, exiting abnormally"
_NESTED = "2026-06-20 10:23:49,345 [myid:1] - WARN  [QuorumPeer[myid=1]:Follower@123] - Exception when following the leader"


@pytest.fixture
def parser():
    return ZookeeperParser()


def test_info(parser):
    e = parser.parse_line(_INFO, 1)
    assert e.severity == Severity.INFO
    assert e.extra["myid"] == "1"
    assert e.extra["class"] == "QuorumPeerMain"


def test_warn(parser):
    assert parser.parse_line(_WARN, 1).severity == Severity.WARNING


def test_error(parser):
    assert parser.parse_line(_ERR, 1).severity == Severity.ERROR


def test_nested_bracket_thread(parser):
    e = parser.parse_line(_NESTED, 1)
    assert e is not None
    assert e.extra["thread"] == "QuorumPeer[myid=1]"
    assert e.extra["class"] == "Follower"


def test_can_parse_by_content():
    assert ZookeeperParser.can_parse(None, [_INFO])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
