"""Tests for the 30 additional log-format parsers:

JSON loggers: pino, bunyan, serilog, winston, suricata, minio, wazuh, azure,
modsecurity. App/server logs: pylogging, log4j, uvicorn, werkzeug, django,
rails, uwsgi. Package managers: dpkg, apthistory, yum. Servers/infra: unbound,
powerdns, nats, mosquitto, nagios, pgbouncer. Cloud: cloudfront, iis. CI /
telephony: githubactions, maven, asterisk.

Each parser must (a) extract the right severity/message and (b) win detection
against the registry without poaching a neighbouring format.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.asterisk import AsteriskParser
from logcrux.parsers.azure import AzureParser
from logcrux.parsers.bunyan import BunyanParser
from logcrux.parsers.cloudfront import CloudFrontParser
from logcrux.parsers.django import DjangoParser
from logcrux.parsers.dpkg import DpkgParser
from logcrux.parsers.githubactions import GitHubActionsParser
from logcrux.parsers.iis import IISParser
from logcrux.parsers.log4j import Log4jParser
from logcrux.parsers.maven import MavenParser
from logcrux.parsers.minio import MinioParser
from logcrux.parsers.modsecurity import ModSecurityParser
from logcrux.parsers.mosquitto import MosquittoParser
from logcrux.parsers.nagios import NagiosParser
from logcrux.parsers.nats import NatsParser
from logcrux.parsers.pgbouncer import PgBouncerParser
from logcrux.parsers.pino import PinoParser
from logcrux.parsers.powerdns import PowerDNSParser
from logcrux.parsers.pylogging import PyLoggingParser
from logcrux.parsers.rails import RailsParser
from logcrux.parsers.registry import detect_parser
from logcrux.parsers.serilog import SerilogParser
from logcrux.parsers.suricata import SuricataParser
from logcrux.parsers.unbound import UnboundParser
from logcrux.parsers.uvicorn import UvicornParser
from logcrux.parsers.uwsgi import UwsgiParser
from logcrux.parsers.wazuh import WazuhParser
from logcrux.parsers.werkzeug import WerkzeugParser
from logcrux.parsers.winston import WinstonParser

FIXTURES = Path(__file__).parent.parent.parent / "fixtures"


# --------------------------------------------------------------------------- #
# Detection: every fixture must resolve to its own parser (no poaching).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "fixture,fmt",
    [
        ("pino", "pino"), ("bunyan", "bunyan"), ("serilog", "serilog"),
        ("winston", "winston"), ("suricata", "suricata"), ("minio", "minio"),
        ("wazuh", "wazuh"), ("azure", "azure"), ("modsecurity", "modsecurity"),
        ("pylogging", "pylogging"), ("log4j", "log4j"), ("uvicorn", "uvicorn"),
        ("werkzeug", "werkzeug"), ("django", "django"), ("rails", "rails"),
        ("dpkg", "dpkg"), ("apt_history", "apthistory"), ("yum", "yum"),
        ("unbound", "unbound"), ("powerdns", "powerdns"), ("nats", "nats"),
        ("mosquitto", "mosquitto"), ("uwsgi", "uwsgi"), ("nagios", "nagios"),
        ("cloudfront", "cloudfront"), ("iis", "iis"), ("pgbouncer", "pgbouncer"),
        ("githubactions", "githubactions"), ("maven", "maven"),
        ("asterisk", "asterisk"),
    ],
)
def test_detection_no_poaching(fixture, fmt):
    lines = (FIXTURES / f"{fixture}.log").read_text().splitlines()
    parser = detect_parser(FIXTURES / f"{fixture}.log", lines[:25])
    assert parser.FORMAT_NAME == fmt


# --------------------------------------------------------------------------- #
# JSON loggers
# --------------------------------------------------------------------------- #
def test_pino_numeric_levels_and_epoch_ms():
    p = PinoParser()
    e = p.parse_line('{"level":50,"time":1718877303789,"pid":12,"msg":"boom"}', 1)
    assert e.severity == Severity.ERROR
    assert e.message == "boom"
    assert e.timestamp is not None and e.timestamp.year == 2024
    # a bunyan line (carries "v":0) is left to BunyanParser at detection time
    assert not PinoParser.can_parse(None, ['{"level":30,"time":1,"msg":"ok","v":0}'])
    assert p.parse_line("plain text", 2) is None


def test_bunyan_requires_v0_marker():
    p = BunyanParser()
    e = p.parse_line(
        '{"name":"app","hostname":"h","pid":1,"level":40,"msg":"warn","time":"2026-06-20T10:15:02.000Z","v":0}',
        1,
    )
    assert e.severity == Severity.WARNING
    assert e.source == "app"
    assert p.parse_line('{"level":30,"time":1,"msg":"x"}', 2) is None  # pino, not bunyan


def test_serilog_clef_default_info_and_exception():
    p = SerilogParser()
    info = p.parse_line('{"@t":"2026-06-20T10:15:01.123Z","@m":"hi"}', 1)
    assert info.severity == Severity.INFO  # @l omitted == Information
    err = p.parse_line(
        '{"@t":"2026-06-20T10:15:03Z","@m":"bad","@l":"Error","@x":"Exc"}', 2
    )
    assert err.severity == Severity.ERROR
    assert err.extra["exception"] == "Exc"


def test_winston_string_levels_and_stack():
    p = WinstonParser()
    e = p.parse_line(
        '{"level":"error","message":"timeout","timestamp":"2026-06-20T10:15:03Z","stack":"Error: t"}',
        1,
    )
    assert e.severity == Severity.ERROR
    # does not poach Azure activity records
    assert p.parse_line(
        '{"level":"Information","message":"x","timestamp":"t","operationName":"op"}', 2
    ) is None


def test_suricata_alert_severity_mapping():
    p = SuricataParser()
    high = p.parse_line(
        '{"timestamp":"2026-06-20T10:15:03+0000","flow_id":3,"event_type":"alert",'
        '"src_ip":"9.9.9.9","dest_ip":"10.0.0.1","alert":{"signature":"RCE","severity":1}}',
        1,
    )
    assert high.severity == Severity.CRITICAL
    assert "RCE" in high.message
    flow = p.parse_line(
        '{"timestamp":"2026-06-20T10:15:01+0000","flow_id":1,"event_type":"flow","src_ip":"1.2.3.4"}',
        2,
    )
    assert flow.severity == Severity.INFO


def test_minio_errkind_and_nested_error():
    p = MinioParser()
    e = p.parse_line(
        '{"level":"ERROR","errKind":"ALL","time":"2026-06-20T10:15:03Z",'
        '"error":{"message":"disk full"}}',
        1,
    )
    assert e.severity == Severity.ERROR
    assert "disk full" in e.message


def test_wazuh_rule_level_buckets():
    p = WazuhParser()
    crit = p.parse_line(
        '{"timestamp":"2026-06-20T10:15:04+0000","rule":{"level":12,"description":"rootkit","id":"510"},"agent":{"name":"w"}}',
        1,
    )
    assert crit.severity == Severity.CRITICAL
    med = p.parse_line(
        '{"timestamp":"2026-06-20T10:15:02+0000","rule":{"level":5,"description":"auth fail"},"agent":{"name":"w"}}',
        2,
    )
    assert med.severity == Severity.WARNING
    assert med.message == "auth fail"


def test_azure_failure_escalates_and_level():
    p = AzureParser()
    e = p.parse_line(
        '{"time":"2026-06-20T10:15:03Z","operationName":"vm/delete","category":"Administrative",'
        '"level":"Error","resultType":"Failure"}',
        1,
    )
    assert e.severity == Severity.ERROR
    assert "vm/delete" in e.message


def test_modsecurity_critical_block():
    p = ModSecurityParser()
    e = p.parse_line(
        '{"transaction":{"time":"20/Jun/2026:10:15:03 +0000","client_ip":"9.9.9.9",'
        '"request":{"method":"POST","uri":"/login"}},"audit_data":{"messages":'
        '["Access denied with code 403 [severity \\"CRITICAL\\"]"]}}',
        1,
    )
    assert e.severity == Severity.CRITICAL
    assert e.extra["client_ip"] == "9.9.9.9"


# --------------------------------------------------------------------------- #
# App / server text logs
# --------------------------------------------------------------------------- #
def test_pylogging_levels():
    p = PyLoggingParser()
    e = p.parse_line("2026-06-20 10:15:03,789 - myapp.db - ERROR - boom", 1)
    assert e.severity == Severity.ERROR
    assert e.source == "myapp.db"
    assert e.message == "boom"
    crit = p.parse_line("2026-06-20 10:15:04,000 - w - CRITICAL - died", 2)
    assert crit.severity == Severity.CRITICAL


def test_pylogging_traceback_folds_into_event():
    # A Python traceback is part of the ERROR event that raised it — it must
    # neither be dropped as unparsed nor push detection to the generic parser.
    lines = [
        "2026-06-20 10:15:03,789 - app.web - ERROR - unhandled exception\n",
        "Traceback (most recent call last):\n",
        '  File "/app/server.py", line 42, in handle\n',
        "    result = do_work(payload)\n",
        "KeyError: 'key'\n",
        "2026-06-20 10:15:04,000 - app.web - INFO - recovered\n",
    ]
    assert PyLoggingParser.can_parse(None, [ln.rstrip("\n") for ln in lines])
    p = PyLoggingParser()
    events = list(p.parse_stream(iter(lines)))
    assert len(events) == 2
    assert "KeyError: 'key'" in events[0].message
    assert p.meta_lines == 4  # traceback lines consumed, not data loss


def test_log4j_java_stacktrace_folds_into_event():
    lines = [
        "2026-06-20 10:15:03,789 [main] ERROR com.example.Service - request failed\n",
        "java.lang.NullPointerException: oops\n",
        "\tat com.example.Service.handle(Service.java:42)\n",
        "Caused by: java.lang.IllegalStateException: bad\n",
        "\t... 12 more\n",
        "2026-06-20 10:15:04,000 [main] INFO com.example.Service - recovered\n",
    ]
    assert Log4jParser.can_parse(None, [ln.rstrip("\n") for ln in lines])
    p = Log4jParser()
    events = list(p.parse_stream(iter(lines)))
    assert len(events) == 2
    assert "NullPointerException" in events[0].message
    assert p.meta_lines == 4


def test_log4j_thread_and_logger():
    p = Log4jParser()
    e = p.parse_line(
        "2026-06-20 10:15:03,789 [http-exec-1] ERROR com.example.Service - refused", 1
    )
    assert e.severity == Severity.ERROR
    assert e.extra["thread"] == "http-exec-1"
    assert e.source == "com.example.Service"


def test_uvicorn_access_5xx_escalates():
    p = UvicornParser()
    e = p.parse_line('INFO:     10.0.0.5:51000 - "POST /api/pay HTTP/1.1" 500 Internal Server Error', 1)
    assert e.severity == Severity.ERROR
    assert e.extra["status"] == 500
    warn = p.parse_line("WARNING:  Invalid HTTP request received.", 2)
    assert warn.severity == Severity.WARNING


def test_werkzeug_status_severity():
    p = WerkzeugParser()
    e = p.parse_line('10.0.0.5 - - [20/Jun/2026 10:15:04] "POST /api/pay HTTP/1.1" 500 -', 1)
    assert e.severity == Severity.ERROR
    assert e.extra["status"] == 500
    # a real Apache/CLF combined line (colon + tz) must NOT be claimed
    assert p.parse_line(
        '1.2.3.4 - - [20/Jun/2026:10:15:04 +0000] "GET / HTTP/1.1" 200 12', 2
    ) is None


def test_django_request_and_control():
    p = DjangoParser()
    e = p.parse_line('[20/Jun/2026 10:15:04] "POST /api/orders/ HTTP/1.1" 500 145', 1)
    assert e.severity == Severity.ERROR
    ok = p.parse_line('[20/Jun/2026 10:15:01] "GET /api/users/ HTTP/1.1" 200 1234', 2)
    assert ok.severity == Severity.INFO


def test_rails_completed_status():
    p = RailsParser()
    e = p.parse_line("Completed 500 Internal Server Error in 8ms (ActiveRecord: 1.0ms)", 1)
    assert e.severity == Severity.ERROR
    started = p.parse_line(
        'Started GET "/users/1" for 127.0.0.1 at 2026-06-20 10:15:01 +0000', 2
    )
    assert started.severity == Severity.INFO
    assert started.extra["method"] == "GET"


def test_uwsgi_request_status():
    p = UwsgiParser()
    e = p.parse_line(
        "[pid: 1234|app: 0|req: 3/3] 10.0.0.5 () {46 vars in 1100 bytes} "
        "[Thu Jun 20 10:15:03 2026] POST /api/pay => generated 200 bytes in 50 msecs "
        "(HTTP/1.1 500) 2 headers in 80 bytes (1 switches on core 0)",
        1,
    )
    assert e.severity == Severity.ERROR
    assert e.extra["status"] == 500
    assert e.extra["duration_ms"] == 50


# --------------------------------------------------------------------------- #
# Package managers
# --------------------------------------------------------------------------- #
def test_dpkg_half_configured_warns():
    p = DpkgParser()
    e = p.parse_line("2026-06-20 10:15:03 status half-configured openssl:amd64 3.0.7-1", 1)
    assert e.severity == Severity.WARNING
    ok = p.parse_line("2026-06-20 10:15:02 status installed nginx:amd64 1.24.0-1", 2)
    assert ok.severity == Severity.INFO


def test_dpkg_disappear_action_parsed():
    p = DpkgParser()
    line = "2026-06-20 10:15:02 disappear libssl1.1:amd64 1.1.1n-0+deb11u5"
    e = p.parse_line(line, 1)
    assert e is not None, "'disappear' action returned None"
    assert e.extra["action"] == "disappear"


def test_apthistory_error_field():
    from logcrux.parsers.apthistory import AptHistoryParser

    p = AptHistoryParser()
    e = p.parse_line("Error: Sub-process /usr/bin/dpkg returned an error code (1)", 1)
    assert e.severity == Severity.ERROR
    inst = p.parse_line("Install: nginx:amd64 (1.24.0-1)", 2)
    assert inst.severity == Severity.INFO


def test_yum_actions():
    from logcrux.parsers.yum import YumParser

    p = YumParser()
    e = p.parse_line("Jun 20 10:15:01 Installed: nginx-1.24.0-1.el9.x86_64", 1)
    assert e.severity == Severity.INFO
    assert e.extra["action"] == "Installed"
    assert e.timestamp is not None


# --------------------------------------------------------------------------- #
# Servers / infra
# --------------------------------------------------------------------------- #
def test_unbound_levels_and_epoch():
    p = UnboundParser()
    e = p.parse_line("[1718877303] unbound[12345:0] error: bind: address already in use", 1)
    assert e.severity == Severity.ERROR
    assert e.timestamp is not None and e.timestamp.year == 2024


def test_powerdns_error_keyword():
    p = PowerDNSParser()
    e = p.parse_line(
        "Jun 20 10:15:03 ns1 pdns_server[1234]: Error: cannot bind to socket", 1
    )
    assert e.severity == Severity.ERROR
    assert e.source == "pdns_server"


def test_nats_level_codes():
    p = NatsParser()
    e = p.parse_line(
        "[1] 2026/06/20 10:15:04.000000 [ERR] Error accepting client connection", 1
    )
    assert e.severity == Severity.ERROR
    warn = p.parse_line("[1] 2026/06/20 10:15:03.000000 [WRN] authentication error", 2)
    assert warn.severity == Severity.WARNING


def test_mosquitto_socket_error():
    p = MosquittoParser()
    e = p.parse_line("1718877306: Error: Unable to open log file /var/log/x.", 1)
    assert e.severity == Severity.ERROR
    conn = p.parse_line("1718877303: New connection from 1.2.3.4:5555 on port 1883.", 2)
    assert conn.severity == Severity.INFO


def test_nagios_state_severity():
    p = NagiosParser()
    e = p.parse_line(
        "[1718877303] SERVICE ALERT: web01;HTTP;CRITICAL;HARD;3;HTTP CRITICAL - 500", 1
    )
    assert e.severity == Severity.ERROR
    down = p.parse_line("[1718877304] HOST ALERT: db01;DOWN;HARD;1;Host Unreachable", 2)
    assert down.severity == Severity.ERROR


def test_pgbouncer_level_no_colon():
    p = PgBouncerParser()
    e = p.parse_line(
        "2026-06-20 10:15:04.000 UTC [1234] ERROR S-0x7799: closing because: server login failed",
        1,
    )
    assert e.severity == Severity.ERROR
    assert e.extra["pid"] == "1234"


# --------------------------------------------------------------------------- #
# Cloud W3C access logs (stateful header)
# --------------------------------------------------------------------------- #
def test_cloudfront_header_then_rows():
    p = CloudFrontParser()
    assert p.parse_line("#Version: 1.0", 1) is None
    assert p.parse_line(
        "#Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status",
        2,
    ) is None
    e = p.parse_line("2026-06-20\t10:15:03\tIAD79-C1\t900\t10.0.0.5\tPOST\td.x.net\t/api/pay\t502", 3)
    assert e.severity == Severity.ERROR
    assert e.extra["status"] == 502


def test_iis_header_then_rows():
    p = IISParser()
    assert p.parse_line(
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken",
        1,
    ) is None
    e = p.parse_line(
        "2026-06-20 10:15:03 10.0.0.1 POST /api/pay - 80 - 10.0.0.5 Mozilla/5.0 500 0 0 250", 2
    )
    assert e.severity == Severity.ERROR
    assert e.extra["status"] == 500


# --------------------------------------------------------------------------- #
# CI / telephony
# --------------------------------------------------------------------------- #
def test_githubactions_commands():
    p = GitHubActionsParser()
    err = p.parse_line("2026-06-20T10:15:05.0000000Z ##[error]Process completed with exit code 1.", 1)
    assert err.severity == Severity.ERROR
    assert err.extra["command"] == "error"
    warn = p.parse_line("2026-06-20T10:15:04.0000000Z ##[warning]deprecated", 2)
    assert warn.severity == Severity.WARNING
    plain = p.parse_line("2026-06-20T10:15:01.1234567Z Current runner version", 3)
    assert plain.severity == Severity.INFO


def test_maven_build_failure():
    p = MavenParser()
    e = p.parse_line("[ERROR] Failed to execute goal: Compilation failure", 1)
    assert e.severity == Severity.ERROR
    fail = p.parse_line("[INFO] BUILD FAILURE", 2)
    assert fail.severity == Severity.ERROR  # escalated despite INFO tag


def test_asterisk_levels():
    p = AsteriskParser()
    e = p.parse_line("[Jun 20 10:15:04] ERROR[1234] pbx.c: Error parsing dialplan extension", 1)
    assert e.severity == Severity.ERROR
    sec = p.parse_line(
        "[Jun 20 10:15:05] SECURITY[1234][C-1] res.c: Failed authentication from 1.2.3.4", 2
    )
    assert sec.severity == Severity.WARNING
    assert sec.extra["call_id"] == "C-1"


def test_unparseable_lines_return_none():
    for parser in (
        PinoParser(), BunyanParser(), SerilogParser(), WinstonParser(),
        SuricataParser(), MinioParser(), WazuhParser(), AzureParser(),
        ModSecurityParser(), PyLoggingParser(), Log4jParser(), UvicornParser(),
        WerkzeugParser(), DjangoParser(), RailsParser(), UwsgiParser(),
        DpkgParser(), UnboundParser(), PowerDNSParser(), NatsParser(),
        MosquittoParser(), NagiosParser(), PgBouncerParser(), CloudFrontParser(),
        IISParser(), GitHubActionsParser(), MavenParser(), AsteriskParser(),
    ):
        assert parser.parse_line("this is not a matching line at all", 1) is None
