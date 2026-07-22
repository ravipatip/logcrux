from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.generic import GenericParser


@pytest.fixture
def parser():
    return GenericParser()


def test_can_parse_always_true(parser):
    assert GenericParser.can_parse(None, []) is True
    assert GenericParser.can_parse(Path("/any/file"), ["anything"]) is True


def test_parse_line_with_iso_timestamp(parser):
    line = "2026-06-16T03:42:00Z ERROR Something went wrong"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.timestamp is not None


def test_parse_line_with_error_keyword(parser):
    # "failure" triggers ERROR via whole-word match. "critical" is lowercase and
    # lacks a strong marker (no UPPER-CASE token or delimited field), so it is
    # treated as an adjective and must NOT elevate severity to CRITICAL.
    event = parser.parse_line("critical failure in module X", 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_parse_preserves_raw(parser):
    line = "some random log line with no structure"
    event = parser.parse_line(line, 5)
    assert event is not None
    assert event.raw == line
    assert event.line_number == 5


def test_severity_not_matched_inside_identifiers(parser):
    # "error"/"fail" embedded in identifiers or method names must NOT be read as
    # an ERROR severity — substring matching here floods free-text logs (e.g.
    # macOS install.log) with thousands of false errors.
    for line in (
        "installer[539]: -[IFDInstallController _buildInstallPlanReturningError:]: ok",
        "loaded NSError category and errorDomain helpers",
        "terror movie playback finished successfully",
    ):
        event = parser.parse_line(line, 1)
        assert event is not None
        assert event.severity != Severity.ERROR, line


def test_severity_matched_as_whole_word(parser):
    assert parser.parse_line("connection failed: timeout", 1).severity == Severity.ERROR
    assert parser.parse_line("request failure on upstream", 1).severity == Severity.ERROR
    assert parser.parse_line("WARN slow query detected", 1).severity == Severity.WARNING
    assert parser.parse_line("a warning about disk usage", 1).severity == Severity.WARNING


def test_keyword_as_count_or_code_is_not_a_level(parser):
    # Free-text logs (macOS install.log) mention severity words as counts, error
    # codes, and adjectives, not as the line's level. Reading these as real
    # errors floods analysis with thousands of false incidents.
    for line in (
        "SCNetworkSetEstablishDefaultConfiguration returned 0 error Success!",
        "/: unable to restore flags 0x80000 (error 30)",
        "BackgroundActions: 0 Critical product(s) - [download]",
        "Received Critical updates: [ [] ]",
        "installing 4 products: Critical [], Config-data [012]",
    ):
        sev = parser.parse_line(line, 1).severity
        assert sev not in (Severity.ERROR, Severity.CRITICAL), line


def test_numeric_field_before_uppercase_level_is_a_level(parser):
    # Many formats put a numeric field (PID/worker id) right before the level
    # label: "<ts> <pid> LEVEL logger msg" (OpenStack/nova and other "<pid>
    # LEVEL" shapes fall to the generic parser). The count guard must not read
    # the PID as a count of the ALL-CAPS level token, or a warning/critical
    # flood in any such format reads as UNKNOWN and goes undetected.
    assert parser.parse_line(
        "2026-07-21 10:00:00 25746 WARNING nova.compute resource nearly exhausted", 1
    ).severity == Severity.WARNING
    assert parser.parse_line(
        "2026-07-21 10:00:00 25746 INFO nova.osapi GET /v2/servers 200", 1
    ).severity == Severity.INFO
    assert parser.parse_line(
        "2026-07-21 10:00:00 25746 CRITICAL nova.compute host down", 1
    ).severity == Severity.CRITICAL
    # ...but a lower/mixed-case count is still not a level.
    assert parser.parse_line("0 warnings emitted", 1).severity != Severity.WARNING
    assert parser.parse_line("2 failures ignored", 1).severity != Severity.ERROR


def test_critical_level_requires_strong_marker(parser):
    # A capitalised adjective ("Critical updates") must not raise a CRITICAL
    # incident, but an upper-case token or a delimited level field is a real
    # CRITICAL level.
    assert parser.parse_line("Critical updates: []", 1).severity != Severity.CRITICAL
    assert parser.parse_line("[CRITICAL] disk controller offline", 1).severity == \
        Severity.CRITICAL
    assert parser.parse_line("level=critical subsystem failed", 1).severity == \
        Severity.CRITICAL
    assert parser.parse_line("FATAL: cannot bind socket", 1).severity == Severity.CRITICAL
