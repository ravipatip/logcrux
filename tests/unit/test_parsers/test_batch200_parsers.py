"""Tests for the 40 parsers that take logcrux from 160 to 200 formats.

Storage / FS: ceph, zfs, mdadm, glusterfs. Virtualization / containers:
libvirt, podman, lxc, qemu, vmware. Big-data / JVM: hbase, hive, flink, druid,
trino. App servers / frameworks: jetty, wildfly, puma, laravel, phperror.
Languages: gostdlib, phoenix. Mail: rspamd, spamassassin, opendkim. Network:
pihole, frr, mikrotik, unifi. Linux daemons: dbus, polkit, apparmor, snapd,
bluetoothd, avahi, rsyslog, syslogng. Agents / PaaS: telegraf, kibana, gitea,
nextcloud.

Each parser must (a) win detection against the full registry without poaching a
neighbouring format and (b) extract the right severity/message/fields.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.apparmor import AppArmorParser
from logcrux.parsers.ceph import CephParser
from logcrux.parsers.frr import FrrParser
from logcrux.parsers.glusterfs import GlusterFSParser
from logcrux.parsers.gostdlib import GoStdlibParser
from logcrux.parsers.hbase import HBaseParser
from logcrux.parsers.hive import HiveParser
from logcrux.parsers.kibana import KibanaParser
from logcrux.parsers.laravel import LaravelParser
from logcrux.parsers.libvirt import LibvirtParser
from logcrux.parsers.lxc import LxcParser
from logcrux.parsers.mdadm import MdadmParser
from logcrux.parsers.mikrotik import MikroTikParser
from logcrux.parsers.nextcloud import NextcloudParser
from logcrux.parsers.opendkim import OpenDKIMParser
from logcrux.parsers.phoenix import PhoenixParser
from logcrux.parsers.phperror import PHPErrorParser
from logcrux.parsers.pihole import PiholeParser
from logcrux.parsers.podman import PodmanParser
from logcrux.parsers.puma import PumaParser
from logcrux.parsers.qemu import QemuParser
from logcrux.parsers.registry import detect_parser
from logcrux.parsers.rspamd import RspamdParser
from logcrux.parsers.rsyslog import RsyslogParser
from logcrux.parsers.spamassassin import SpamAssassinParser
from logcrux.parsers.syslogng import SyslogNgParser
from logcrux.parsers.telegraf import TelegrafParser
from logcrux.parsers.trino import TrinoParser
from logcrux.parsers.vmware import VMwareParser
from logcrux.parsers.wildfly import WildflyParser
from logcrux.parsers.zfs import ZfsParser

FIXTURES = Path(__file__).parent.parent.parent / "fixtures"

NEW_FORMATS = [
    "ceph", "zfs", "mdadm", "glusterfs", "libvirt", "podman", "lxc", "qemu",
    "vmware", "hbase", "hive", "flink", "druid", "trino", "jetty", "wildfly",
    "puma", "laravel", "phperror", "gostdlib", "phoenix", "rspamd",
    "spamassassin", "opendkim", "pihole", "frr", "mikrotik", "unifi", "dbus",
    "polkit", "apparmor", "snapd", "bluetoothd", "avahi", "rsyslog", "syslogng",
    "telegraf", "kibana", "gitea", "nextcloud",
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
    lines = (FIXTURES / f"{fixture}.log").read_text().splitlines()
    parser = detect_parser(None, lines[:25])
    events = _parse_file(parser, fixture)
    total = len([ln for ln in lines if ln.strip()])
    assert len(events) >= total * 0.8


# --------------------------------------------------------------------------- #
# Storage / filesystem
# --------------------------------------------------------------------------- #
def test_ceph_channel_severity():
    events = _parse_file(CephParser(), "ceph")
    assert any(e.extra.get("channel") == "ERR" and e.severity == Severity.ERROR
               for e in events)
    assert any(e.extra.get("channel") == "WRN" and e.severity == Severity.WARNING
               for e in events)
    assert events[0].extra.get("thread")


def test_zfs_event_class_severity():
    events = _parse_file(ZfsParser(), "zfs")
    checksum = next(e for e in events if e.extra.get("event_class") == "checksum")
    assert checksum.severity == Severity.ERROR
    assert any(e.severity == Severity.WARNING for e in events)  # statechange/scrub
    assert all(e.extra.get("pool") == "tank" for e in events)


def test_mdadm_fail_and_rebuild():
    events = _parse_file(MdadmParser(), "mdadm")
    fail = next(e for e in events if e.extra.get("event") == "Fail")
    assert fail.severity == Severity.ERROR
    assert fail.extra["device"] == "/dev/md0"
    assert any(e.severity == Severity.WARNING for e in events)  # Rebuild/SpareActive


def test_glusterfs_level_letters():
    events = _parse_file(GlusterFSParser(), "glusterfs")
    assert any(e.severity == Severity.CRITICAL for e in events)  # C
    assert any(e.severity == Severity.ERROR for e in events)     # E
    assert any(e.severity == Severity.WARNING for e in events)   # W
    assert any(e.extra.get("msgid") for e in events)


# --------------------------------------------------------------------------- #
# Virtualization / containers
# --------------------------------------------------------------------------- #
def test_libvirt_levels_and_location():
    events = _parse_file(LibvirtParser(), "libvirt")
    err = next(e for e in events if e.severity == Severity.ERROR)
    assert err.extra.get("location")
    assert any(e.severity == Severity.WARNING for e in events)


def test_podman_actions_severity():
    events = _parse_file(PodmanParser(), "podman")
    assert any(e.extra.get("action") == "died" and e.severity == Severity.ERROR
               for e in events)
    assert any(e.extra.get("name") == "web" for e in events)
    assert events[0].extra["type"] == "container"


def test_lxc_level_and_container():
    events = _parse_file(LxcParser(), "lxc")
    assert all(e.extra.get("container") == "web" for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert events[0].timestamp is not None


def test_qemu_severity():
    events = _parse_file(QemuParser(), "qemu")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert any(e.extra.get("program", "").startswith("qemu-") for e in events)


def test_vmware_marker_severity():
    events = _parse_file(VMwareParser(), "vmware")
    assert any(e.extra.get("level") == "ALERT" and e.severity == Severity.CRITICAL
               for e in events)
    assert any(e.extra.get("level") == "WARNING" and e.severity == Severity.WARNING
               for e in events)
    assert events[0].extra.get("cpu") == "0"


# --------------------------------------------------------------------------- #
# Big-data / JVM
# --------------------------------------------------------------------------- #
def test_hbase_vocab_and_levels():
    events = _parse_file(HBaseParser(), "hbase")
    assert any("hbase" in (e.extra.get("logger", "") + e.message).lower()
               or "HRegionServer" in e.message for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)


def test_hive_vocab_and_levels():
    events = _parse_file(HiveParser(), "hive")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert any("hive" in (e.extra.get("logger", "") + e.message).lower() for e in events)


def test_trino_logger_and_levels():
    events = _parse_file(TrinoParser(), "trino")
    assert all(e.extra.get("logger", "").startswith(("io.trino", "io.prestosql"))
               for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert events[0].timestamp is not None


# --------------------------------------------------------------------------- #
# Application servers / frameworks
# --------------------------------------------------------------------------- #
def test_wildfly_code_and_levels():
    events = _parse_file(WildflyParser(), "wildfly")
    assert any(e.extra.get("code", "").startswith("WFLY") for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)


def test_puma_marker_severity():
    events = _parse_file(PumaParser(), "puma")
    err = next(e for e in events if e.extra.get("marker") == "!")
    assert err.severity == Severity.ERROR
    assert any(e.extra.get("pid") == "12345" for e in events)


def test_laravel_env_and_levels():
    events = _parse_file(LaravelParser(), "laravel")
    assert all(e.extra.get("env") == "production" for e in events)
    assert any(e.severity == Severity.CRITICAL for e in events)
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)


def test_phperror_severity_scale():
    events = _parse_file(PHPErrorParser(), "phperror")
    assert any(e.severity == Severity.CRITICAL for e in events)  # Fatal error
    assert any(e.severity == Severity.ERROR for e in events)     # Parse error
    assert any(e.severity == Severity.WARNING for e in events)   # Warning
    assert any(e.extra.get("error_type") == "Fatal error" for e in events)


# --------------------------------------------------------------------------- #
# Languages
# --------------------------------------------------------------------------- #
def test_gostdlib_severity_and_src():
    events = _parse_file(GoStdlibParser(), "gostdlib")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert any(e.extra.get("src", "").endswith(".go:42") for e in events)


def test_phoenix_levels():
    events = _parse_file(PhoenixParser(), "phoenix")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert any(e.extra.get("level") == "debug" for e in events)


# --------------------------------------------------------------------------- #
# Mail
# --------------------------------------------------------------------------- #
def test_rspamd_module_and_severity():
    events = _parse_file(RspamdParser(), "rspamd")
    assert any(e.extra.get("module") == "task" for e in events)
    assert any(e.severity == Severity.WARNING for e in events)  # greylist
    assert any(e.severity == Severity.ERROR for e in events)    # reject / cannot connect


def test_spamassassin_verdict_and_error():
    events = _parse_file(SpamAssassinParser(), "spamassassin")
    spam = next(e for e in events if e.extra.get("verdict") == "spam")
    assert spam.severity == Severity.WARNING
    assert any(e.severity == Severity.ERROR for e in events)  # failed to load Bayes


def test_opendkim_queue_id_and_severity():
    events = _parse_file(OpenDKIMParser(), "opendkim")
    assert any(e.extra.get("queue_id") == "5SAF1234" for e in events)
    assert any(e.severity == Severity.WARNING for e in events)  # no signature
    assert any(e.severity == Severity.ERROR for e in events)    # bad signature / failed


# --------------------------------------------------------------------------- #
# Network
# --------------------------------------------------------------------------- #
def test_pihole_severity():
    events = _parse_file(PiholeParser(), "pihole")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert all(e.extra.get("pid") for e in events)


def test_frr_daemon_and_severity():
    events = _parse_file(FrrParser(), "frr")
    daemons = {e.extra.get("daemon") for e in events}
    assert {"bgpd", "ospfd", "zebra"} <= daemons
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)


def test_mikrotik_topics_and_severity():
    events = _parse_file(MikroTikParser(), "mikrotik")
    assert any(e.severity == Severity.WARNING for e in events)
    assert any(e.severity == Severity.CRITICAL for e in events)
    assert any("firewall" in e.extra.get("topics", "") for e in events)


# --------------------------------------------------------------------------- #
# Linux daemons / agents
# --------------------------------------------------------------------------- #
def test_dbus_failure_is_error():
    events = _parse_file(detect_parser(None, (FIXTURES / "dbus.log").read_text().splitlines()), "dbus")
    assert any(e.severity == Severity.ERROR for e in events)  # Failed to activate
    assert all(e.source == "dbus" for e in events)


def test_apparmor_denied_is_warning():
    events = _parse_file(AppArmorParser(), "apparmor")
    denied = [e for e in events if e.extra.get("apparmor") == "DENIED"]
    assert len(denied) == 2
    assert all(e.severity == Severity.WARNING for e in denied)
    assert denied[0].extra.get("profile") == "/usr/sbin/mysqld"
    assert denied[0].extra.get("operation") == "open"


def test_rsyslog_severity():
    events = _parse_file(RsyslogParser(), "rsyslog")
    assert any(e.severity == Severity.ERROR for e in events)    # cannot connect / refused
    assert any(e.severity == Severity.WARNING for e in events)  # suspended / retry
    assert all(e.source == "rsyslog" for e in events)


def test_syslogng_error_and_warning():
    events = _parse_file(SyslogNgParser(), "syslogng")
    assert any(e.severity == Severity.ERROR for e in events)    # Error opening / broken
    assert any(e.severity == Severity.WARNING for e in events)  # reload / suspending
    assert all(e.source == "syslog-ng" for e in events)


def test_telegraf_component_and_severity():
    events = _parse_file(TelegrafParser(), "telegraf")
    assert any(e.extra.get("component") == "agent" for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert any(e.severity == Severity.ERROR for e in events)


def test_kibana_tags_and_severity():
    events = _parse_file(KibanaParser(), "kibana")
    assert any(e.severity == Severity.ERROR for e in events)
    assert any(e.severity == Severity.WARNING for e in events)
    assert any("listening" in e.extra.get("tags", "") for e in events)


def test_nextcloud_numeric_level_scale():
    events = _parse_file(NextcloudParser(), "nextcloud")
    assert any(e.severity == Severity.CRITICAL for e in events)  # level 4
    assert any(e.severity == Severity.ERROR for e in events)     # level 3
    assert any(e.severity == Severity.WARNING for e in events)   # level 2
    assert all(e.extra.get("reqId") for e in events)


# --------------------------------------------------------------------------- #
# Cross-format anti-poaching spot checks
# --------------------------------------------------------------------------- #
def test_hbase_hive_not_hadoop():
    hbase = (FIXTURES / "hbase.log").read_text().splitlines()
    hive = (FIXTURES / "hive.log").read_text().splitlines()
    assert detect_parser(None, hbase[:25]).FORMAT_NAME == "hbase"
    assert detect_parser(None, hive[:25]).FORMAT_NAME == "hive"


def test_gitea_not_gostdlib():
    gitea = (FIXTURES / "gitea.log").read_text().splitlines()
    # Gitea's "src.go:line:func() [L]" must win over the broad Go stdlib parser.
    assert detect_parser(None, gitea[:25]).FORMAT_NAME == "gitea"


def test_plain_go_log_not_gitea():
    go_lines = [
        "2026/06/28 10:15:01 starting up",
        "2026/06/28 10:15:02 listening on :9000",
        "2026/06/28 10:15:03 request handled in 2ms",
    ]
    assert detect_parser(None, go_lines).FORMAT_NAME == "gostdlib"
