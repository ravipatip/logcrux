"""Tests for the 30 parsers that take logcrux from 130 to 160 formats.

Mail / identity / VPN: sendmail, opensmtpd, sssd, krb5kdc, tailscale, wpa_
supplicant. Security / antivirus / audit: clamav, falco, osquery, okta. Web /
proxy / CDN: lighttpd, cloudflare, kong, s3access. Config-mgmt / orchestration:
puppet, saltstack, chef, certbot. App / job / build: airflow, sidekiq, jvmgc.
Databases / big-data: cockroachdb, hadoop, spark, neo4j, solr. Monitoring /
infra / desktop: monit, zabbix, rsyncd, xorg.

Each parser must (a) win detection against the full registry without poaching a
neighbouring format and (b) extract the right severity/message/fields.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.airflow import AirflowParser
from logcrux.parsers.certbot import CertbotParser
from logcrux.parsers.chef import ChefParser
from logcrux.parsers.clamav import ClamAVParser
from logcrux.parsers.cloudflare import CloudflareParser
from logcrux.parsers.cockroachdb import CockroachDBParser
from logcrux.parsers.falco import FalcoParser
from logcrux.parsers.hadoop import HadoopParser
from logcrux.parsers.jvmgc import JvmGcParser
from logcrux.parsers.kong import KongParser
from logcrux.parsers.krb5kdc import Krb5KdcParser
from logcrux.parsers.lighttpd import LighttpdParser
from logcrux.parsers.monit import MonitParser
from logcrux.parsers.neo4j import Neo4jParser
from logcrux.parsers.okta import OktaParser
from logcrux.parsers.opensmtpd import OpenSMTPDParser
from logcrux.parsers.osquery import OsqueryParser
from logcrux.parsers.puppet import PuppetParser
from logcrux.parsers.registry import detect_parser
from logcrux.parsers.rsyncd import RsyncdParser
from logcrux.parsers.s3access import S3AccessParser
from logcrux.parsers.saltstack import SaltStackParser
from logcrux.parsers.sendmail import SendmailParser
from logcrux.parsers.sidekiq import SidekiqParser
from logcrux.parsers.solr import SolrParser
from logcrux.parsers.spark import SparkParser
from logcrux.parsers.sssd import SssdParser
from logcrux.parsers.tailscale import TailscaleParser
from logcrux.parsers.wpa_supplicant import WpaSupplicantParser
from logcrux.parsers.xorg import XorgParser
from logcrux.parsers.zabbix import ZabbixParser

FIXTURES = Path(__file__).parent.parent.parent / "fixtures"

NEW_FORMATS = [
    "sendmail", "opensmtpd", "sssd", "krb5kdc", "clamav", "puppet", "tailscale",
    "falco", "osquery", "okta", "cloudflare", "kong", "lighttpd", "airflow",
    "sidekiq", "cockroachdb", "xorg", "wpa_supplicant", "s3access", "monit",
    "zabbix", "rsyncd", "certbot", "saltstack", "chef", "jvmgc", "hadoop",
    "spark", "neo4j", "solr",
]


def _parse_file(parser, name: str):
    lines = (FIXTURES / f"{name}.log").read_text().splitlines()
    events = []
    for i, line in enumerate(lines, start=1):
        ev = parser.parse_line(line, i)
        if ev is not None:
            events.append(ev)
    return events


# --------------------------------------------------------------------------- #
# Detection: every fixture must resolve to its own parser (no poaching), and the
# choice must survive the registry's generic-fallback coverage check.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fixture", NEW_FORMATS)
def test_detection_no_poaching(fixture):
    lines = (FIXTURES / f"{fixture}.log").read_text().splitlines()
    parser = detect_parser(FIXTURES / f"{fixture}.log", lines[:25])
    assert parser.FORMAT_NAME == fixture


@pytest.mark.parametrize("fixture", NEW_FORMATS)
def test_parser_covers_fixture(fixture):
    """Each parser must parse (not silently drop) the bulk of its own fixture."""
    parser = detect_parser(None, (FIXTURES / f"{fixture}.log").read_text().splitlines()[:25])
    events = _parse_file(parser, fixture)
    total = len([ln for ln in (FIXTURES / f"{fixture}.log").read_text().splitlines() if ln.strip()])
    assert len(events) >= total * 0.8


# --------------------------------------------------------------------------- #
# Mail / identity / VPN
# --------------------------------------------------------------------------- #
def test_sendmail_stat_and_severity():
    events = _parse_file(SendmailParser(), "sendmail")
    sent = next(e for e in events if e.extra.get("stat") == "Sent")
    assert sent.severity == Severity.INFO
    assert sent.extra["queue_id"].startswith("5SAF")
    assert any(e.severity == Severity.WARNING for e in events)  # Deferred
    assert any(e.severity == Severity.ERROR for e in events)    # reject / User unknown


def test_opensmtpd_delivery_results():
    events = _parse_file(OpenSMTPDParser(), "opensmtpd")
    assert any(e.extra.get("result") == "Ok" for e in events)
    assert any(e.severity == Severity.WARNING for e in events)  # TempFail
    assert any(e.severity == Severity.ERROR for e in events)    # mta error / failed-command


def test_sssd_component_and_offline_error():
    events = _parse_file(SssdParser(), "sssd")
    assert any(e.extra.get("component", "").startswith("be[") for e in events)
    assert any(e.severity == Severity.ERROR for e in events)    # Failed to connect
    assert any(e.severity == Severity.WARNING for e in events)  # Going offline


def test_krb5kdc_request_type_and_failure():
    events = _parse_file(Krb5KdcParser(), "krb5kdc")
    assert any(e.extra.get("request_type") == "AS_REQ" for e in events)
    assert any(e.extra.get("request_type") == "TGS_REQ" for e in events)
    # "Decrypt integrity check failed" / "Client not found" -> ERROR.
    assert any(e.severity == Severity.ERROR for e in events)


def test_tailscale_subsystem_and_warning():
    events = _parse_file(TailscaleParser(), "tailscale")
    assert any(e.extra.get("subsystem") == "magicsock" for e in events)
    assert any(e.severity == Severity.WARNING for e in events)  # handshake failed
    assert events[0].timestamp is not None


def test_wpa_supplicant_events():
    events = _parse_file(WpaSupplicantParser(), "wpa_supplicant")
    assert all(e.extra.get("interface") == "wlan0" for e in events)
    assert any(e.severity == Severity.ERROR for e in events)    # DISCONNECTED / TEMP-DISABLED
    assert any("CONNECTED" in e.message for e in events)


# --------------------------------------------------------------------------- #
# Security / antivirus / audit
# --------------------------------------------------------------------------- #
def test_clamav_virus_found_is_critical():
    events = _parse_file(ClamAVParser(), "clamav")
    found = [e for e in events if "infected_path" in e.extra]
    assert len(found) == 2
    assert all(e.severity == Severity.CRITICAL for e in found)
    assert found[0].extra["signature"].startswith("Win.Trojan")
    assert any(e.severity == Severity.ERROR for e in events)    # config ERROR
    assert any(e.severity == Severity.WARNING for e in events)  # OUTDATED


def test_falco_priority_scale():
    events = _parse_file(FalcoParser(), "falco")
    assert any(e.severity == Severity.CRITICAL for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    crit = next(e for e in events if e.severity == Severity.CRITICAL)
    assert crit.extra["rule"] == "Unexpected outbound connection"


def test_osquery_action_and_columns():
    events = _parse_file(OsqueryParser(), "osquery")
    assert any(e.extra.get("action") == "removed" and e.severity == Severity.WARNING
               for e in events)
    assert events[0].timestamp is not None
    assert "nc" in events[0].message


def test_okta_failure_outcome_escalates():
    events = _parse_file(OktaParser(), "okta")
    fail = next(e for e in events if e.extra.get("result") == "FAILURE")
    assert fail.severity == Severity.WARNING
    deny = next(e for e in events if e.extra.get("result") == "DENY")
    assert deny.severity == Severity.WARNING
    assert events[0].extra["eventType"] == "user.session.start"


# --------------------------------------------------------------------------- #
# Web / proxy / CDN
# --------------------------------------------------------------------------- #
def test_lighttpd_severity():
    events = _parse_file(LighttpdParser(), "lighttpd")
    assert any(e.severity == Severity.ERROR for e in events)    # Fatal error / backend error
    assert any(e.severity == Severity.WARNING for e in events)  # timeout
    assert events[0].extra["src"].endswith(".c.1558")


def test_cloudflare_status_and_waf():
    events = _parse_file(CloudflareParser(), "cloudflare")
    assert any(e.severity == Severity.ERROR for e in events)    # 500
    blocked = next(e for e in events if e.extra.get("waf_action") == "block")
    assert blocked.severity == Severity.WARNING
    assert all(e.extra.get("ray_id") for e in events)


def test_kong_status_to_severity():
    events = _parse_file(KongParser(), "kong")
    assert any(e.severity == Severity.ERROR for e in events)    # 502
    assert any(e.severity == Severity.WARNING for e in events)  # 401
    assert any(e.extra.get("service") == "orders-service" for e in events)


def test_s3access_operation_and_status():
    events = _parse_file(S3AccessParser(), "s3access")
    assert events[0].extra["operation"] == "REST.GET.OBJECT"
    assert events[0].extra["bucket"] == "example-bucket"
    assert any(e.extra.get("error_code") == "AccessDenied" and e.severity == Severity.WARNING
               for e in events)
    assert events[0].timestamp is not None


# --------------------------------------------------------------------------- #
# Config-management / orchestration / CI
# --------------------------------------------------------------------------- #
def test_puppet_resource_and_error():
    events = _parse_file(PuppetParser(), "puppet")
    assert any(e.extra.get("resource", "").startswith("/Stage[main]") for e in events)
    assert any(e.severity == Severity.ERROR for e in events)    # Could not retrieve catalog


def test_saltstack_levels():
    events = _parse_file(SaltStackParser(), "saltstack")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert all(e.extra.get("logger", "").startswith("salt") for e in events)


def test_chef_levels():
    events = _parse_file(ChefParser(), "chef")
    assert any(e.severity == Severity.CRITICAL for e in events)  # FATAL
    assert any(e.severity == Severity.ERROR for e in events)
    assert events[0].timestamp is not None


def test_certbot_module_and_error():
    events = _parse_file(CertbotParser(), "certbot")
    assert all(e.extra["module"].startswith(("certbot", "acme")) for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)


# --------------------------------------------------------------------------- #
# Application / job / build
# --------------------------------------------------------------------------- #
def test_airflow_levels_and_source():
    events = _parse_file(AirflowParser(), "airflow")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert events[0].extra["src"].startswith("taskinstance.py")


def test_sidekiq_both_header_styles():
    events = _parse_file(SidekiqParser(), "sidekiq")
    # classic "PID TID-xxx" and modern "pid= tid=" headers both parse.
    assert any(e.extra.get("tid") == "oabc12" for e in events)
    assert any(e.extra.get("jid") == "9f8e7d6c5b4a" for e in events)
    assert any(e.severity == Severity.ERROR for e in events)


def test_jvmgc_tags_and_warning():
    events = _parse_file(JvmGcParser(), "jvmgc")
    assert any("gc" in e.extra.get("tags", "") for e in events)
    assert any(e.severity == Severity.WARNING for e in events)  # allocation stall
    assert events[0].timestamp is not None


# --------------------------------------------------------------------------- #
# Databases / big-data
# --------------------------------------------------------------------------- #
def test_cockroachdb_levels_and_tags():
    events = _parse_file(CockroachDBParser(), "cockroachdb")
    assert any(e.severity == Severity.CRITICAL for e in events)  # F + disk full
    assert any(e.severity == Severity.WARNING for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert events[0].extra.get("tags") == "n1"


def test_hadoop_logger_and_levels():
    events = _parse_file(HadoopParser(), "hadoop")
    assert any(e.extra.get("logger", "").startswith("org.apache.hadoop") for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)


def test_spark_logger_and_levels():
    events = _parse_file(SparkParser(), "spark")
    assert any("spark" in e.extra.get("logger", "") for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)


def test_neo4j_logger_and_levels():
    events = _parse_file(Neo4jParser(), "neo4j")
    assert any(e.extra.get("logger", "").startswith("o.n.") for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert events[0].timestamp is not None


def test_solr_context_and_levels():
    events = _parse_file(SolrParser(), "solr")
    assert any(e.extra.get("context") == "x:books" for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)


# --------------------------------------------------------------------------- #
# Monitoring / infra
# --------------------------------------------------------------------------- #
def test_monit_resource_alert():
    events = _parse_file(MonitParser(), "monit")
    assert any(e.extra.get("service") == "rootfs" and e.severity == Severity.ERROR
               for e in events)
    assert any(e.severity == Severity.WARNING for e in events)  # loadavg


def test_zabbix_severity_and_pid():
    events = _parse_file(ZabbixParser(), "zabbix")
    assert all(e.extra.get("pid") for e in events)
    assert any(e.severity == Severity.ERROR for e in events)    # query failed / cannot connect
    assert any(e.severity == Severity.WARNING for e in events)  # slow query
    assert events[0].timestamp is not None


def test_rsyncd_auth_and_error():
    events = _parse_file(RsyncdParser(), "rsyncd")
    assert any(e.severity == Severity.WARNING for e in events)  # auth failed
    assert any(e.severity == Severity.ERROR for e in events)    # rsync error code 12
    assert all(e.extra.get("pid") for e in events)


def test_xorg_marker_severity():
    events = _parse_file(XorgParser(), "xorg")
    assert any(e.extra.get("marker") == "EE" and e.severity == Severity.ERROR
               for e in events)
    assert any(e.extra.get("marker") == "WW" and e.severity == Severity.WARNING
               for e in events)


# --------------------------------------------------------------------------- #
# Cross-format anti-poaching spot checks
# --------------------------------------------------------------------------- #
def test_cockroachdb_not_klog():
    # A klog line (4-digit MMDD, no "⋮") must NOT be claimed by CockroachDBParser.
    klog = ["I0628 10:15:01.123456 1 server.go:100] kube-apiserver starting"]
    assert detect_parser(None, klog).FORMAT_NAME != "cockroachdb"


def test_hadoop_not_spark_and_vice_versa():
    hadoop_lines = (FIXTURES / "hadoop.log").read_text().splitlines()
    spark_lines = (FIXTURES / "spark.log").read_text().splitlines()
    assert detect_parser(None, hadoop_lines[:25]).FORMAT_NAME == "hadoop"
    assert detect_parser(None, spark_lines[:25]).FORMAT_NAME == "spark"


def test_generic_log4j_not_hijacked_by_hadoop_or_spark():
    # A plain log4j log with no Hadoop/Spark vocabulary stays log4j.
    log4j = [
        "2026-06-28 10:15:01,123 [main] INFO  com.example.App - started",
        "2026-06-28 10:15:02,456 [pool-1] ERROR com.example.Svc - boom",
    ]
    name = detect_parser(None, log4j).FORMAT_NAME
    assert name not in ("hadoop", "spark", "neo4j", "solr")


# --- Real-world default layouts: Spark %d{yy/MM/dd} and classic HDFS %d{yyMMdd} ---
# These are the shapes actual production Spark-on-YARN / HDFS corpora ship;
# both were falling to the generic parser, losing every timestamp.

def test_spark_yymmdd_slash_format():
    lines = [
        "17/06/09 20:10:40 INFO executor.CoarseGrainedExecutorBackend: Registered signal handlers for [TERM, HUP, INT]",
        "17/06/09 20:10:40 INFO spark.SecurityManager: Changing view acls to: yarn,curi",
        "17/06/09 20:11:11 WARN storage.BlockManager: Putting block rdd_2_2 failed",
        "17/06/09 20:11:12 ERROR executor.Executor: Exception in task 1.0 in stage 2.0",
    ]
    assert detect_parser(None, lines).FORMAT_NAME == "spark"
    parser = SparkParser()
    events = [parser.parse_line(ln, i + 1) for i, ln in enumerate(lines)]
    assert all(e is not None for e in events)
    assert events[0].timestamp is not None
    assert events[0].timestamp.year == 2017
    assert events[2].severity == Severity.WARNING
    assert events[3].severity == Severity.ERROR


def test_hadoop_classic_hdfs_format():
    lines = [
        "081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating",
        "081109 204005 35 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated",
        "081109 204842 663 WARN dfs.DataNode$DataXceiver: 10.251.65.203:50010: Got exception while serving blk_1",
        "081109 204845 664 ERROR dfs.DataNode: DataXceiver error processing READ_BLOCK operation",
    ]
    assert detect_parser(None, lines).FORMAT_NAME == "hadoop"
    parser = HadoopParser()
    events = [parser.parse_line(ln, i + 1) for i, ln in enumerate(lines)]
    assert all(e is not None for e in events)
    assert events[0].timestamp is not None
    assert events[0].timestamp.year == 2008
    assert events[2].severity == Severity.WARNING
    assert events[3].severity == Severity.ERROR
