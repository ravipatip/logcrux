"""Tests for the 26 parsers that take logcrux from 104 to 130 formats.

Security / SIEM / firewall: cef, leef, gelf, ciscoasa, paloalto, fortigate,
zeek, snort, pfsense. Databases: cassandra, clickhouse, mssql, oracle. Auth /
IAM / VPN: keycloak, freeradius, wireguard. Messaging / HA: activemq, pulsar,
patroni. Cloud / observability: logstash, filebeat, datadog. CI / build /
package: gradle, npm, bazel, pip.

Each parser must (a) win detection against the full registry without poaching a
neighbouring format and (b) extract the right severity/message/fields.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.activemq import ActiveMQParser
from logcrux.parsers.bazel import BazelParser
from logcrux.parsers.cassandra import CassandraParser
from logcrux.parsers.cef import CEFParser
from logcrux.parsers.ciscoasa import CiscoASAParser
from logcrux.parsers.clickhouse import ClickHouseParser
from logcrux.parsers.datadog import DatadogParser
from logcrux.parsers.filebeat import FilebeatParser
from logcrux.parsers.fortigate import FortiGateParser
from logcrux.parsers.freeradius import FreeRadiusParser
from logcrux.parsers.gelf import GELFParser
from logcrux.parsers.gradle import GradleParser
from logcrux.parsers.keycloak import KeycloakParser
from logcrux.parsers.leef import LEEFParser
from logcrux.parsers.logstash import LogstashParser
from logcrux.parsers.mssql import MSSQLParser
from logcrux.parsers.npm import NpmParser
from logcrux.parsers.oracle import OracleParser
from logcrux.parsers.paloalto import PaloAltoParser
from logcrux.parsers.patroni import PatroniParser
from logcrux.parsers.pfsense import PfSenseParser
from logcrux.parsers.pip import PipParser
from logcrux.parsers.pulsar import PulsarParser
from logcrux.parsers.registry import detect_parser
from logcrux.parsers.snort import SnortParser
from logcrux.parsers.wireguard import WireGuardParser
from logcrux.parsers.zeek import ZeekParser

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
# Detection: every fixture must resolve to its own parser (no poaching), and
# the choice must survive the registry's generic-fallback coverage check (a
# representative log is data-dominated, so the dedicated parser is kept).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "fixture",
    [
        "cef", "leef", "gelf", "ciscoasa", "paloalto", "fortigate", "zeek",
        "snort", "pfsense", "cassandra", "clickhouse", "mssql", "oracle",
        "keycloak", "freeradius", "wireguard", "activemq", "pulsar", "patroni",
        "logstash", "filebeat", "datadog", "gradle", "npm", "bazel", "pip",
    ],
)
def test_detection_no_poaching(fixture):
    lines = (FIXTURES / f"{fixture}.log").read_text().splitlines()
    parser = detect_parser(FIXTURES / f"{fixture}.log", lines[:25])
    assert parser.FORMAT_NAME == fixture


# --------------------------------------------------------------------------- #
# SIEM / firewall / IDS
# --------------------------------------------------------------------------- #
def test_cef_severity_scale_and_name():
    events = _parse_file(CEFParser(), "cef")
    # "worm successfully stopped" with severity 6 -> WARNING; message is Name.
    assert events[0].message == "worm successfully stopped"
    assert events[0].severity == Severity.WARNING
    # severity 9 -> CRITICAL, 3 -> INFO
    assert any(e.severity == Severity.CRITICAL for e in events)
    assert any(e.severity == Severity.INFO for e in events)


def test_cef_handles_syslog_prefix():
    parser = CEFParser()
    ev = parser.parse_line(
        "Jun 20 10:15:05 fw1 CEF:0|Fortinet|FortiGate|6.4|0421|IPS hit|7|src=1.2.3.4",
        1,
    )
    assert ev is not None
    assert ev.severity == Severity.ERROR
    assert ev.message == "IPS hit"
    assert ev.timestamp is not None


def test_cef_timestamp_from_rt_field():
    parser = CEFParser()
    ev = parser.parse_line(
        "CEF:0|ArcSight|SIEM|1.0|400|Event|7|src=10.0.0.5 rt=1718877301000 dst=10.0.0.80",
        1,
    )
    assert ev is not None
    assert ev.timestamp is not None
    assert ev.timestamp.year >= 2024


def test_leef_tab_and_caret_delimiters():
    events = _parse_file(LEEFParser(), "leef")
    # sev=9 -> CRITICAL via tab-delimited attributes
    assert any(e.severity == Severity.CRITICAL for e in events)
    # The caret-delimited LEEF 2.0 line parses its sev=8 -> ERROR
    caret = [e for e in events if e.extra.get("sev") == "8"]
    assert caret and caret[0].severity == Severity.ERROR


def test_leef_timestamp_from_syslog_header():
    parser = LEEFParser()
    ev = parser.parse_line(
        "Jun 20 10:15:05 siem1 LEEF:1.0|IBM|QRadar|2.0|4000|src=10.0.0.1\tsev=6\tmsg=Port scan",
        1,
    )
    assert ev is not None
    assert ev.timestamp is not None


def test_leef_timestamp_from_devtime():
    parser = LEEFParser()
    ev = parser.parse_line(
        "LEEF:1.0|IBM|QRadar|2.0|5000|src=10.0.0.2\tsev=5\tdevTime=2026-06-20T10:15:01.000Z\tmsg=Test",
        1,
    )
    assert ev is not None
    assert ev.timestamp is not None
    assert ev.timestamp.year == 2026


def test_gelf_syslog_numeric_levels():
    events = _parse_file(GELFParser(), "gelf")
    # level 3 -> ERROR, level 2 -> CRITICAL, level 6 -> INFO
    assert events[0].severity == Severity.INFO
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.CRITICAL for e in events)
    assert events[0].timestamp is not None


def test_ciscoasa_severity_from_tag():
    events = _parse_file(CiscoASAParser(), "ciscoasa")
    # %ASA-6 -> INFO, %ASA-4 -> WARNING, %ASA-3 -> ERROR, %ASA-2/1 -> CRITICAL
    sevs = {e.extra["syslog_severity"]: e.severity for e in events}
    assert sevs[6] == Severity.INFO
    assert sevs[4] == Severity.WARNING
    assert sevs[3] == Severity.ERROR
    assert sevs[2] == Severity.CRITICAL


def test_paloalto_threat_severity_and_type():
    events = _parse_file(PaloAltoParser(), "paloalto")
    types = {e.extra["log_type"] for e in events}
    assert {"TRAFFIC", "THREAT", "SYSTEM"} <= types
    # The "critical" THREAT line escalates to CRITICAL.
    assert any(e.severity == Severity.CRITICAL for e in events)


def test_fortigate_level_and_action():
    events = _parse_file(FortiGateParser(), "fortigate")
    crit = [e for e in events if e.severity == Severity.CRITICAL]
    assert crit  # the HA-failure line is level="critical"
    # A deny action on a notice-level line escalates to WARNING.
    assert any(e.extra.get("action") == "deny" and e.severity == Severity.WARNING for e in events)


def test_zeek_conn_state_severity():
    events = _parse_file(ZeekParser(), "zeek")
    # SF flows are INFO; REJ/S0/RSTO are WARNING.
    assert any(e.severity == Severity.INFO for e in events)
    assert any(e.severity == Severity.WARNING and e.extra.get("conn_state") in
               {"REJ", "S0", "RSTO"} for e in events)
    # Header lines produce no events.
    assert all(not e.raw.startswith("#") for e in events)


def test_snort_priority_to_severity():
    events = _parse_file(SnortParser(), "snort")
    # Priority 1 -> ERROR, 2 -> WARNING, 3 -> INFO
    by_prio = {e.extra.get("priority"): e.severity for e in events}
    assert by_prio[1] == Severity.ERROR
    assert by_prio[2] == Severity.WARNING
    assert by_prio[3] == Severity.INFO
    assert events[0].message == "ET SCAN Potential SSH Scan"


def test_pfsense_block_vs_pass():
    events = _parse_file(PfSenseParser(), "pfsense")
    assert any(e.extra["action"] == "block" and e.severity == Severity.WARNING for e in events)
    assert any(e.extra["action"] == "pass" and e.severity == Severity.INFO for e in events)
    blocked = [e for e in events if e.extra["action"] == "block"][0]
    assert blocked.extra["dst"] == "10.0.0.80"


# --------------------------------------------------------------------------- #
# Databases
# --------------------------------------------------------------------------- #
def test_cassandra_level_first_layout():
    events = _parse_file(CassandraParser(), "cassandra")
    assert events[0].severity == Severity.INFO
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert events[0].timestamp is not None


def test_clickhouse_angle_bracket_levels():
    events = _parse_file(ClickHouseParser(), "clickhouse")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.CRITICAL for e in events)  # <Fatal>
    assert any(e.severity == Severity.WARNING for e in events)
    assert events[0].extra["level"] == "information"


def test_mssql_login_failed_and_severity_field():
    events = _parse_file(MSSQLParser(), "mssql")
    assert any("Login failed" in e.message and e.severity == Severity.WARNING for e in events)
    # "Severity: 17" -> CRITICAL
    assert any(e.severity == Severity.CRITICAL for e in events)


def test_oracle_ora_codes_severity():
    events = _parse_file(OracleParser(), "oracle")
    ora600 = [e for e in events if e.extra.get("error_code") == "ORA-00600"]
    assert ora600 and ora600[0].severity == Severity.CRITICAL
    # ORA-19809 (recovery file limit) is a non-critical ORA error -> ERROR
    assert any(e.extra.get("error_code") == "ORA-19809" and e.severity == Severity.ERROR
               for e in events)
    # The timestamp header is carried onto the lines beneath it.
    assert ora600[0].timestamp is not None


# --------------------------------------------------------------------------- #
# Auth / IAM / VPN
# --------------------------------------------------------------------------- #
def test_keycloak_login_error_escalates():
    events = _parse_file(KeycloakParser(), "keycloak")
    login_errors = [e for e in events if e.extra.get("event_type") == "LOGIN_ERROR"]
    assert login_errors
    assert all(e.severity == Severity.WARNING for e in login_errors)
    assert any(e.severity == Severity.ERROR for e in events)  # KeycloakErrorHandler


def test_freeradius_failed_auth_is_warning():
    events = _parse_file(FreeRadiusParser(), "freeradius")
    assert any("Login incorrect" in e.message and e.severity == Severity.WARNING for e in events)
    assert any("Login OK" in e.message and e.severity == Severity.INFO for e in events)
    assert any(e.severity == Severity.ERROR for e in events)


def test_wireguard_retry_is_warning():
    events = _parse_file(WireGuardParser(), "wireguard")
    assert any("did not complete" in e.message and e.severity == Severity.WARNING
               for e in events)
    assert any(e.extra.get("peer") for e in events)


# --------------------------------------------------------------------------- #
# Messaging / HA
# --------------------------------------------------------------------------- #
def test_activemq_pipe_layout():
    events = _parse_file(ActiveMQParser(), "activemq")
    assert events[0].message.startswith("Using Persistence Adapter")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert events[0].extra["logger"].startswith("org.apache.activemq")


def test_pulsar_iso_timestamp_log4j2():
    events = _parse_file(PulsarParser(), "pulsar")
    assert events[0].timestamp is not None
    assert any(e.severity == Severity.ERROR for e in events)
    assert events[0].extra["logger"].startswith("org.apache.pulsar")


def test_patroni_level_colon():
    events = _parse_file(PatroniParser(), "patroni")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert events[0].message.startswith("Selected new etcd server")


# --------------------------------------------------------------------------- #
# Cloud / observability
# --------------------------------------------------------------------------- #
def test_logstash_requires_logstash_logger():
    events = _parse_file(LogstashParser(), "logstash")
    assert any(e.severity == Severity.ERROR for e in events)
    assert all(e.extra["logger"].startswith("logstash") for e in events)


def test_logstash_does_not_grab_elasticsearch():
    # An Elasticsearch line shares the bracket shape but has an o.e.* logger.
    es_line = "[2026-06-20T10:15:01,123][INFO ][o.e.n.Node               ] [node-1] starting"
    assert LogstashParser.can_parse(None, [es_line]) is False


def test_filebeat_ecs_dotted_keys():
    events = _parse_file(FilebeatParser(), "filebeat")
    assert events[0].timestamp is not None
    assert any(e.severity == Severity.ERROR for e in events)
    assert events[0].extra["service"] == "filebeat"


def test_datadog_pipe_and_timezone():
    events = _parse_file(DatadogParser(), "datadog")
    assert events[0].timestamp is not None
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert events[0].extra["agent"] == "CORE"


# --------------------------------------------------------------------------- #
# CI / build / package
# --------------------------------------------------------------------------- #
def test_gradle_task_failed_and_build_failed():
    events = _parse_file(GradleParser(), "gradle")
    assert any(e.extra.get("status") == "FAILED" and e.severity == Severity.ERROR
               for e in events)
    assert any("BUILD FAILED" in e.message and e.severity == Severity.ERROR for e in events)


def test_npm_levels():
    events = _parse_file(NpmParser(), "npm")
    assert any(e.extra["level"] == "err!" and e.severity == Severity.ERROR for e in events)
    assert any(e.extra["level"] == "warn" and e.severity == Severity.WARNING for e in events)


def test_bazel_level_and_marker_gate():
    events = _parse_file(BazelParser(), "bazel")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.CRITICAL for e in events)  # FAILED:
    # Without a Bazel-specific phrase, a bare "INFO:" log is not claimed.
    assert BazelParser.can_parse(None, ["INFO: just an app message", "INFO: another"]) is False


def test_bazel_compiler_diagnostics_parsed():
    # "file.cc:42:5: error: ..." lines carry the actual failure cause and must
    # not be dropped as unparsed.
    events = _parse_file(BazelParser(), "bazel")
    diags = [e for e in events if e.source == "src/main.cc"]
    assert diags and diags[0].severity == Severity.ERROR
    assert "was not declared" in diags[0].message


def test_pip_error_and_progress():
    events = _parse_file(PipParser(), "pip")
    assert any(e.message.startswith("Could not find a version") and e.severity == Severity.ERROR
               for e in events)
    assert any(e.message.startswith("Collecting") and e.severity == Severity.INFO for e in events)
