"""Tests for the Ping Identity product-family parsers.

Covers PingFederate (server.log Log4j2 "tid:" shape + pipe-delimited security/
admin audit), PingAccess (pingaccess.log + pipe-delimited engine/API audit), and
the shared Ping Data platform format used by PingDirectory / PingDirectoryProxy /
PingDataSync / PingAuthorize (LDAP access log + category=/severity= error log).

Each parser must (a) win detection against the full registry without poaching a
neighbouring format (notably ActiveMQ's pipe layout, generic log4j, and Apache
access) and (b) extract the right severity/message/fields.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.pingaccess import PingAccessParser
from logcrux.parsers.pingauthorize import PingAuthorizeParser
from logcrux.parsers.pingdirectory import PingDirectoryParser
from logcrux.parsers.pingfederate import PingFederateParser
from logcrux.parsers.pingintelligence import PingIntelligenceParser
from logcrux.parsers.registry import detect_parser

FIXTURES = Path(__file__).parent.parent.parent / "fixtures"


def _parse_file(parser, name: str):
    lines = (FIXTURES / f"{name}.log").read_text().splitlines()
    events = []
    for i, line in enumerate(lines, start=1):
        ev = parser.parse_line(line, i)
        if ev is not None:
            events.append(ev)
    return events


# --------------------------------------------------------------------------- #
# Detection: each fixture resolves to the right parser, surviving the registry's
# generic-fallback coverage check.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "fixture,fmt",
    [
        ("pingfederate", "pingfederate"),
        ("pingfederate_audit", "pingfederate"),
        ("pingaccess", "pingaccess"),
        ("pingaccess_audit", "pingaccess"),
        ("pingdirectory", "pingdirectory"),
        ("pingdatasync", "pingdirectory"),
        ("pingauthorize", "pingauthorize"),
        ("pingintelligence", "pingintelligence"),
    ],
)
def test_detection_no_poaching(fixture, fmt):
    lines = (FIXTURES / f"{fixture}.log").read_text().splitlines()
    parser = detect_parser(FIXTURES / f"{fixture}.log", lines[:25])
    assert parser.FORMAT_NAME == fmt


@pytest.mark.parametrize(
    "fixture,cls",
    [
        ("pingfederate", PingFederateParser),
        ("pingfederate_audit", PingFederateParser),
        ("pingaccess", PingAccessParser),
        ("pingaccess_audit", PingAccessParser),
        ("pingdirectory", PingDirectoryParser),
        ("pingdatasync", PingDirectoryParser),
        ("pingauthorize", PingAuthorizeParser),
        ("pingintelligence", PingIntelligenceParser),
    ],
)
def test_parser_covers_fixture(fixture, cls):
    lines = (FIXTURES / f"{fixture}.log").read_text().splitlines()
    events = _parse_file(cls(), fixture)
    total = len([ln for ln in lines if ln.strip()])
    assert len(events) >= total * 0.8


# --------------------------------------------------------------------------- #
# PingFederate
# --------------------------------------------------------------------------- #
def test_pingfederate_server_levels_and_tid():
    events = _parse_file(PingFederateParser(), "pingfederate")
    assert events[0].extra["tid"] == "Z8I1vdotGu084PB7b2HrQ0A1kKU"
    assert events[0].extra["logger"].startswith("org.sourceid")
    assert any(e.severity == Severity.WARNING for e in events)   # invalid creds
    assert any(e.severity == Severity.ERROR for e in events)     # signature fail
    assert any(e.severity == Severity.CRITICAL for e in events)  # FATAL start


def test_pingfederate_audit_failure_is_warning():
    events = _parse_file(PingFederateParser(), "pingfederate_audit")
    failures = [e for e in events if e.severity == Severity.WARNING]
    assert len(failures) >= 2  # two AUTHN failures + one OAuth denied
    assert all(e.source == "pingfederate-audit" for e in failures)
    ok = next(e for e in events if "Login was successful" in e.message)
    assert ok.severity == Severity.INFO


def test_pingfederate_audit_not_confused_with_activemq():
    """An ActiveMQ pipe line (field 2 is a level) must not resolve to Ping."""
    activemq_line = (
        "2026-06-20 10:15:02,456 | WARN  | Transport Connection failed | "
        "o.a.a.broker.TransportConnector | Transport"
    )
    parser = detect_parser(None, [activemq_line])
    assert parser.FORMAT_NAME == "activemq"


# --------------------------------------------------------------------------- #
# PingAccess
# --------------------------------------------------------------------------- #
def test_pingaccess_server_levels_and_exchange():
    events = _parse_file(PingAccessParser(), "pingaccess")
    assert events[0].extra["exchange_id"] == "exchange-41"
    assert events[0].extra["logger"].startswith("com.pingidentity")
    assert any(e.severity == Severity.WARNING for e in events)  # token validation
    assert any(e.severity == Severity.ERROR for e in events)    # site connect refused


def test_pingaccess_audit_response_code_severity():
    events = _parse_file(PingAccessParser(), "pingaccess_audit")
    by_code = {e.extra["response_code"]: e for e in events}
    assert by_code["200"].severity == Severity.INFO
    assert by_code["401"].severity == Severity.WARNING
    assert by_code["403"].severity == Severity.WARNING
    assert by_code["502"].severity == Severity.ERROR


def test_pingaccess_does_not_poach_generic_log4j():
    """A non-Ping log4j line (no com.pingidentity logger) must not resolve here."""
    line = "2025-09-02T11:02:32,869  INFO [exchange-1] org.apache.catalina.Foo:10 - x"
    assert PingAccessParser.can_parse(None, [line]) is False


# --------------------------------------------------------------------------- #
# PingDirectory (Ping Data platform)
# --------------------------------------------------------------------------- #
def test_pingdirectory_error_severity_map():
    events = _parse_file(PingDirectoryParser(), "pingdirectory")
    notice = next(e for e in events if e.extra.get("msgID") == "458887")
    assert notice.severity == Severity.INFO
    assert notice.extra["category"] == "CORE"
    severe = next(e for e in events if e.extra.get("category") == "BACKEND")
    assert severe.severity == Severity.ERROR


def test_pingdirectory_failed_bind_is_warning():
    events = _parse_file(PingDirectoryParser(), "pingdirectory")
    failed = [
        e
        for e in events
        if e.extra.get("operation") == "BIND RESULT"
        and e.extra.get("resultCode") == "49"
    ]
    assert len(failed) == 1
    assert failed[0].severity == Severity.WARNING
    ok = next(
        e
        for e in events
        if e.extra.get("operation") == "BIND RESULT"
        and e.extra.get("resultCode") == "0"
    )
    assert ok.severity == Severity.INFO


def test_pingdirectory_not_apache_access():
    """A real Apache access line (IP first, then [ts]) must not resolve here."""
    line = '10.0.0.5 - - [11/Apr/2011:10:31:53 -0500] "GET / HTTP/1.1" 200 12'
    assert PingDirectoryParser.can_parse(None, [line]) is False


# --------------------------------------------------------------------------- #
# PingDataSync (shares the Ping Data platform record shape)
# --------------------------------------------------------------------------- #
def test_pingdatasync_sync_fields_and_source():
    events = _parse_file(PingDirectoryParser(), "pingdatasync")
    synced = next(e for e in events if "Synchronized ADD" in e.message)
    assert synced.source == "pingdatasync"
    assert synced.extra["pipe"] == "ds1_to_PingOne_Destination"
    # The op/changeNumber/pipe fields between msgID and msg must not swallow msg.
    assert synced.message.startswith("Synchronized ADD of uid=user.2")
    assert any(e.severity == Severity.WARNING for e in events)  # MILD_WARNING drop
    assert any(e.severity == Severity.ERROR for e in events)    # SEVERE_ERROR fail


# --------------------------------------------------------------------------- #
# PingAuthorize / PingDataGovernance policy-decision log
# --------------------------------------------------------------------------- #
def test_pingauthorize_decision_severity():
    events = _parse_file(PingAuthorizeParser(), "pingauthorize")
    permit = [e for e in events if e.extra["decision"] == "PERMIT"]
    deny = [e for e in events if e.extra["decision"] == "DENY"]
    indet = [e for e in events if e.extra["decision"] == "INDETERMINATE"]
    assert all(e.severity == Severity.INFO for e in permit)
    assert deny and all(e.severity == Severity.WARNING for e in deny)
    assert indet and all(e.severity == Severity.WARNING for e in indet)


def test_pingauthorize_handles_both_shapes():
    events = _parse_file(PingAuthorizeParser(), "pingauthorize")
    # nested results[].decision shape + top-level decision shape both parse.
    assert any(e.extra["requestId"] == "8245be35-ec9e-40f1-a79a-80890041f4b0"
               for e in events)
    assert any(e.extra["requestId"] == "cda6fd43-e9ae-49de-b822-7479ef2f2b35"
               for e in events)


def test_pingauthorize_does_not_poach_okta():
    """An Okta JSON event (no decision/elapsedTime) must not resolve here."""
    line = (
        '{"eventType":"user.session.start","actor":{"alternateId":"a@x.com"},'
        '"published":"2026-06-28T10:15:01.123Z","severity":"INFO"}'
    )
    assert PingAuthorizeParser.can_parse(None, [line]) is False


# --------------------------------------------------------------------------- #
# PingIntelligence ASE
# --------------------------------------------------------------------------- #
def test_pingintelligence_levels_and_attack_type():
    events = _parse_file(PingIntelligenceParser(), "pingintelligence")
    drop = next(e for e in events if e.extra.get("type") == "connection_drop")
    assert drop.severity == Severity.WARNING  # raised from info for attack type
    assert drop.extra["api"] == "decoy"
    assert drop.extra["client"] == "203.0.113.9:41120"
    assert any(e.severity == Severity.ERROR for e in events)     # backend refused
    assert any(e.severity == Severity.CRITICAL for e in events)  # fatal shutdown
    assert events[0].timestamp is not None


# --------------------------------------------------------------------------- #
# Product-name --format aliases resolve to the right parser
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "alias,fmt",
    [
        ("pingdatasync", "pingdirectory"),
        ("pingdirectoryproxy", "pingdirectory"),
        ("pingdatametrics", "pingdirectory"),
        ("pingdatagovernance", "pingauthorize"),
    ],
)
def test_product_name_aliases(alias, fmt):
    parser = detect_parser(None, [], format_override=alias)
    assert parser.FORMAT_NAME == fmt
