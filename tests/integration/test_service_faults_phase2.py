"""Held-out service faults — real GCP VM captures (phase 2, 2026-10-13).

Each was reported CLEAN, or under the wrong cause, by the first round of
fixes: they are fault types that round was never tuned on.
"""
import json

import pytest
from typer.testing import CliRunner

from logcrux.cli import app
from tests.integration.test_cli import _copy_to_tmp

runner = CliRunner()


def _run(name, tmp_path):
    log = _copy_to_tmp(name, tmp_path)
    return json.loads(runner.invoke(app, [str(log), "--json", "--no-baseline"]).stdout)


@pytest.mark.parametrize("fixture, category", [
    # 40x "[Warning] Access denied for user 'root'@'localhost'" (MariaDB 10.5)
    ("mariadb_authfail_alma9.log", "auth_brute_force"),
    # mariadbd SIGKILLed -> "InnoDB: Starting crash recovery" (MariaDB 10.3)
    ("mariadb_crash_recovery_alma8.log", "service_crash"),
    # MariaDB 11.8 (Leap 16): "Starting table crash recovery..."
    ("mariadb_crash_recovery_leap16.log", "service_crash"),
    # Redis/Valkey's own "crashed by signal: 11" bug report
    ("redis_crash_report_rocky10.log", "service_crash"),
    # "[emerg] unknown directive" -> unit fails; the cause is the config
    ("nginx_config_error_unit_alma9.log", "config_error"),
])
def test_held_out_fault_is_detected_with_its_cause(fixture, category, tmp_path):
    out = _run(fixture, tmp_path)
    assert out["level"] != "CLEAN"
    assert out["category"] == category


def test_config_error_names_the_incident_before_the_crash_it_caused(tmp_path):
    out = _run("nginx_config_error_unit_alma9.log", tmp_path)
    assert out["findings"][0]["headline"] == "Configuration rejected"


@pytest.mark.parametrize("fixture", [
    "redis_crash_report_rocky10.log",   # Valkey 8: "=== VALKEY BUG REPORT START"
    "redis_crash_report_alma8.log",     # Redis 5.0: "=== REDIS BUG REPORT START"
])
def test_crash_report_body_folds_into_the_crash_event(fixture, tmp_path):
    out = _run(fixture, tmp_path)
    assert out["parser_format"] == "redis"
    assert out["level"] == "CRITICAL"
    # Only the report header before the first event is left unparsed.
    assert out["skipped_count"] <= 6


def test_sudo_password_failures_count_the_summary_line(tmp_path):
    # Real SLES 15 SP5: 6 sudo runs x 3 wrong passwords -> one pam failure line
    # per run plus "3 incorrect password attempts" (was CLEAN).
    out = _run("sudo_authfail_sles15sp5.log", tmp_path)
    assert out["level"] != "CLEAN"
    assert out["category"] == "auth_brute_force"


def test_debian_non_sudoer_attempts_are_auth_failures(tmp_path):
    # Real Debian 12: one password prompt, then "user NOT in sudoers", x6.
    out = _run("sudo_not_in_sudoers_debian12.log", tmp_path)
    assert out["category"] == "auth_brute_force"


def test_apparmor_persistent_denial_is_reported(tmp_path):
    out = _run("apparmor_denied_debian12.log", tmp_path)
    assert out["category"] == "config_error"
    assert out["findings"][0]["headline"] == "AppArmor denied access"
    assert "/etc/hostname" in out["findings"][0]["detail"]


def test_healthy_ubuntu_boot_is_clean(tmp_path):
    # systemd unit descriptions ("GRUB failed boot detection", "Process error
    # reports ...") and dhclient's benign AppArmor denials are not incidents.
    out = _run("journal_boot_healthy_ubuntu2204.log", tmp_path)
    assert out["level"] == "CLEAN"


def test_daemon_parser_keeps_other_programs_lines(tmp_path):
    # Real Ubuntu 22.04: rsyslogd owns 25/28 lines of the window; the one
    # kernel "md/raid1: Disk failure" line used to be dropped (CLEAN).
    out = _run("journal_raid_rsyslog_ubuntu2204.log", tmp_path)
    assert out["level"] == "CRITICAL"
    assert out["findings"][0]["headline"] == "RAID array degraded"
