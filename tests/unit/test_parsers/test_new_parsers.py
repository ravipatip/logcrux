"""Tests for the 10 application/middleware parsers added for broad coverage:
mongodb, elasticsearch, kafka, rabbitmq, gunicorn, php-fpm, tomcat, exim,
openvpn, dnsmasq.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.dnsmasq import DnsmasqParser
from logcrux.parsers.elasticsearch import ElasticsearchParser
from logcrux.parsers.exim import EximParser
from logcrux.parsers.gunicorn import GunicornParser
from logcrux.parsers.kafka import KafkaParser
from logcrux.parsers.mongodb import MongoDBParser
from logcrux.parsers.openvpn import OpenVPNParser
from logcrux.parsers.phpfpm import PhpFpmParser
from logcrux.parsers.rabbitmq import RabbitMQParser
from logcrux.parsers.registry import detect_parser
from logcrux.parsers.tomcat import TomcatParser


# --------------------------------------------------------------------------- #
# MongoDB
# --------------------------------------------------------------------------- #
def test_mongodb_json_severity_and_message():
    p = MongoDBParser()
    line = ('{"t":{"$date":"2026-06-20T10:23:48.220+00:00"},"s":"E","c":"STORAGE",'
            '"id":20557,"ctx":"conn42","msg":"Assertion while reading collection",'
            '"attr":{"error":"WriteConflict"}}')
    ev = p.parse_line(line, 1)
    assert ev is not None
    assert ev.severity == Severity.ERROR
    assert ev.timestamp is not None
    assert "Assertion while reading collection" in ev.message
    assert "WriteConflict" in ev.message  # attr folded in
    assert ev.extra["component"] == "STORAGE"


def test_mongodb_fatal_is_critical():
    p = MongoDBParser()
    line = '{"t":{"$date":"2026-06-20T10:23:49.900+00:00"},"s":"F","c":"CONTROL","id":1,"ctx":"main","msg":"Wrong mongod version"}'
    assert p.parse_line(line, 1).severity == Severity.CRITICAL


def test_mongodb_legacy_format():
    p = MongoDBParser()
    line = "2026-06-20T10:23:52.456+0000 E STORAGE  [conn43] WiredTiger error No space left on device"
    ev = p.parse_line(line, 1)
    assert ev is not None
    assert ev.severity == Severity.ERROR
    assert ev.extra["ctx"] == "conn43"


def test_mongodb_invalid_json_returns_none():
    assert MongoDBParser().parse_line("{not valid json", 1) is None
    assert MongoDBParser().parse_line("", 1) is None


def test_mongodb_detected_over_journald():
    sample = ['{"t":{"$date":"2026-06-20T10:23:45.123+00:00"},"s":"I","c":"NETWORK","id":1,"ctx":"x","msg":"ok"}']
    assert isinstance(detect_parser(None, sample), MongoDBParser)


# --------------------------------------------------------------------------- #
# Elasticsearch
# --------------------------------------------------------------------------- #
def test_elasticsearch_levels():
    p = ElasticsearchParser()
    warn = "[2026-06-20T10:23:47,330][WARN ][o.e.c.r.a.DiskThresholdMonitor] [es-node-1] high disk watermark exceeded"
    ev = p.parse_line(warn, 1)
    assert ev.severity == Severity.WARNING
    assert ev.extra["logger"] == "o.e.c.r.a.DiskThresholdMonitor"
    assert ev.extra["node"] == "es-node-1"
    err = "[2026-06-20T10:23:48,440][ERROR][o.e.b.X] [es-node-1] fatal error"
    assert p.parse_line(err, 1).severity == Severity.ERROR


def test_elasticsearch_detected_not_kafka():
    sample = ["[2026-06-20T10:23:45,123][INFO ][o.e.n.Node] [n1] starting"]
    assert isinstance(detect_parser(None, sample), ElasticsearchParser)


# --------------------------------------------------------------------------- #
# Kafka
# --------------------------------------------------------------------------- #
def test_kafka_levels_and_logger():
    p = KafkaParser()
    line = "[2026-06-20 10:23:51,770] FATAL [KafkaServer id=0] Fatal error during shutdown (kafka.server.KafkaServer)"
    ev = p.parse_line(line, 1)
    assert ev.severity == Severity.CRITICAL
    assert ev.extra["logger"] == "kafka.server.KafkaServer"
    assert "Fatal error during shutdown" in ev.message


def test_kafka_detected_not_elasticsearch():
    sample = ["[2026-06-20 10:23:45,123] INFO Registered broker (kafka.zk.KafkaZkClient)"]
    assert isinstance(detect_parser(None, sample), KafkaParser)


# --------------------------------------------------------------------------- #
# RabbitMQ
# --------------------------------------------------------------------------- #
def test_rabbitmq_levels_and_pid():
    p = RabbitMQParser()
    line = "2026-06-20 10:23:48.440 [error] <0.700.0> Error on AMQP connection: closed"
    ev = p.parse_line(line, 1)
    assert ev.severity == Severity.ERROR
    assert ev.extra["erlang_pid"] == "<0.700.0>"
    crit = "2026-06-20 10:23:50.660 [critical] <0.55.0> Cluster partition detected"
    assert p.parse_line(crit, 1).severity == Severity.CRITICAL


def test_rabbitmq_requires_erlang_pid_for_detection():
    # A bare "date [level] msg" without an Erlang pid must not be claimed.
    sample = ["2026-06-20 10:23:48.440 [error] something without pid"]
    assert not isinstance(detect_parser(None, sample), RabbitMQParser)


# --------------------------------------------------------------------------- #
# Gunicorn
# --------------------------------------------------------------------------- #
def test_gunicorn_levels():
    p = GunicornParser()
    line = "[2026-06-20 10:23:50 +0000] [123] [CRITICAL] WORKER TIMEOUT (pid:124)"
    ev = p.parse_line(line, 1)
    assert ev.severity == Severity.CRITICAL
    assert ev.extra["pid"] == "123"
    err = "[2026-06-20 10:23:50 +0000] [124] [ERROR] Worker was sent SIGKILL! Perhaps out of memory?"
    assert p.parse_line(err, 1).severity == Severity.ERROR


def test_gunicorn_detected_not_apache_error():
    sample = ["[2026-06-20 10:23:45 +0000] [123] [INFO] Starting gunicorn 21.2.0"]
    assert isinstance(detect_parser(None, sample), GunicornParser)


# --------------------------------------------------------------------------- #
# PHP-FPM
# --------------------------------------------------------------------------- #
def test_phpfpm_levels_and_pool():
    p = PhpFpmParser()
    line = "[20-Jun-2026 10:23:50] WARNING: [pool www] server reached pm.max_children setting (5)"
    ev = p.parse_line(line, 1)
    assert ev.severity == Severity.WARNING
    assert ev.extra["pool"] == "www"
    assert ev.message.startswith("server reached")
    assert p.parse_line("[20-Jun-2026 10:23:54] ALERT: [pool www] child exited", 1).severity == Severity.CRITICAL


def test_phpfpm_detected():
    sample = ["[20-Jun-2026 10:23:45] NOTICE: fpm is running, pid 1234"]
    assert isinstance(detect_parser(None, sample), PhpFpmParser)


# --------------------------------------------------------------------------- #
# Tomcat
# --------------------------------------------------------------------------- #
def test_tomcat_severe_is_error():
    p = TomcatParser()
    line = "20-Jun-2026 10:23:48.440 SEVERE [http-nio-8080-exec-1] org.apache.catalina.core.StandardWrapperValve.invoke threw exception"
    ev = p.parse_line(line, 1)
    assert ev.severity == Severity.ERROR
    assert ev.extra["thread"] == "http-nio-8080-exec-1"
    assert p.parse_line("20-Jun-2026 10:23:45.123 INFO [main] x.Y.z started", 1).severity == Severity.INFO


def test_tomcat_detected():
    sample = ["20-Jun-2026 10:23:45.123 INFO [main] org.apache.catalina.startup.Catalina.start startup"]
    assert isinstance(detect_parser(None, sample), TomcatParser)


# --------------------------------------------------------------------------- #
# Exim
# --------------------------------------------------------------------------- #
def test_exim_delivery_failure_is_error():
    p = EximParser()
    line = "2026-06-20 10:23:48 1tEFGH-002CD3-4D ** bad@nowhere.invalid: Unrouteable address"
    ev = p.parse_line(line, 1)
    assert ev.severity == Severity.ERROR
    assert ev.extra["flag"] == "**"
    assert ev.extra["msg_id"] == "1tEFGH-002CD3-4D"


def test_exim_arrival_is_info_and_deferral_is_warning():
    p = EximParser()
    arrival = "2026-06-20 10:23:45 1tABCD-001AB2-3C <= sender@example.com H=mail [203.0.113.5] P=esmtps S=2345"
    assert p.parse_line(arrival, 1).severity == Severity.INFO
    defer = "2026-06-20 10:23:49 1tIJKL-003EF4-5E == slow@dest.com R=dnslookup defer (-44): SMTP timeout"
    assert p.parse_line(defer, 1).severity == Severity.WARNING


def test_exim_reject_without_msgid():
    p = EximParser()
    line = "2026-06-20 10:23:50 H=(spammer) [192.0.2.9] F=<phish@bad.com> rejected RCPT <v@example.com>: relay not permitted"
    ev = p.parse_line(line, 1)
    assert ev is not None
    assert ev.severity == Severity.WARNING


def test_exim_detected():
    sample = ["2026-06-20 10:23:45 1tABCD-001AB2-3C <= sender@example.com H=mail [203.0.113.5] P=esmtps S=2345"]
    assert isinstance(detect_parser(None, sample), EximParser)


# --------------------------------------------------------------------------- #
# OpenVPN
# --------------------------------------------------------------------------- #
def test_openvpn_tls_error_is_error():
    p = OpenVPNParser()
    line = "Thu Jun 20 10:23:49 2026 10.0.0.5:1194 TLS Error: TLS handshake failed"
    ev = p.parse_line(line, 1)
    assert ev.severity == Severity.ERROR
    assert ev.timestamp is not None
    assert "TLS handshake failed" in ev.message


def test_openvpn_sigterm_is_warning():
    p = OpenVPNParser()
    line = "Thu Jun 20 10:23:52 2026 client2/10.0.0.6:1194 SIGTERM[soft,ping-restart] received"
    assert p.parse_line(line, 1).severity == Severity.WARNING


def test_openvpn_syslog_tagged():
    p = OpenVPNParser()
    line = "Jun 20 10:23:45 host ovpn-server[123]: TLS Error: TLS handshake failed"
    ev = p.parse_line(line, 1)
    assert ev is not None
    assert ev.severity == Severity.ERROR
    assert ev.extra["program"] == "ovpn-server"


def test_openvpn_detected():
    sample = ["Thu Jun 20 10:23:45 2026 OpenVPN 2.5.9 x86_64 built on Jun 1 2026"]
    assert isinstance(detect_parser(None, sample), OpenVPNParser)


# --------------------------------------------------------------------------- #
# dnsmasq
# --------------------------------------------------------------------------- #
def test_dnsmasq_query_extraction():
    p = DnsmasqParser()
    line = "Jun 20 10:23:46 gw dnsmasq[1234]: query[A] example.com from 10.0.0.5"
    ev = p.parse_line(line, 1)
    assert ev is not None
    assert ev.extra["query_type"] == "A"
    assert ev.extra["domain"] == "example.com"


def test_dnsmasq_no_servers_is_error():
    p = DnsmasqParser()
    line = "Jun 20 10:23:48 gw dnsmasq[1234]: no servers reachable, all upstream DNS servers failed"
    assert p.parse_line(line, 1).severity == Severity.ERROR


def test_dnsmasq_dhcp_subtag():
    p = DnsmasqParser()
    line = "Jun 20 10:23:49 gw dnsmasq-dhcp[1234]: DHCPACK(eth0) 10.0.0.50 00:0c:29:aa:bb:cc laptop"
    ev = p.parse_line(line, 1)
    assert ev is not None
    assert ev.extra["program"] == "dnsmasq-dhcp"


def test_dnsmasq_detected():
    sample = [
        "Jun 20 10:23:45 gw dnsmasq[1234]: started, version 2.85",
        "Jun 20 10:23:46 gw dnsmasq[1234]: query[A] example.com from 10.0.0.5",
    ]
    assert isinstance(detect_parser(None, sample), DnsmasqParser)


# --------------------------------------------------------------------------- #
# Empty-line handling for all parsers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("parser_cls", [
    MongoDBParser, ElasticsearchParser, KafkaParser, RabbitMQParser,
    GunicornParser, PhpFpmParser, TomcatParser, EximParser,
    OpenVPNParser, DnsmasqParser,
])
def test_empty_line_returns_none(parser_cls):
    assert parser_cls().parse_line("", 1) is None


@pytest.mark.parametrize("name", [
    "mongodb", "elasticsearch", "kafka", "rabbitmq", "gunicorn",
    "phpfpm", "tomcat", "exim", "openvpn", "dnsmasq",
])
def test_fixture_files_parse(name):
    path = Path(__file__).parents[2] / "fixtures" / f"{name}.log"
    lines = path.read_text().splitlines()
    parser = detect_parser(path, lines[:20])
    events = list(parser.parse_stream(iter(lines)))
    assert len(events) >= len(lines) - 1  # at most one non-event header line
