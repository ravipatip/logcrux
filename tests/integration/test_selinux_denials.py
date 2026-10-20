"""SELinux AVC denials — real RHEL 10.2 audit.log captures (GCP, 2026-10-13).

The auditd parser read these correctly and logcrux reported CLEAN, on every
enforcing distro tested — even the name_bind denial that stopped nginx from
starting.
"""
import json
from datetime import datetime

import pytest
from typer.testing import CliRunner

from logcrux.analysis.anomaly import analyze_policy_denials
from logcrux.cli import app
from logcrux.models import ParsedEvent, Severity
from tests.integration.test_cli import _copy_to_tmp

runner = CliRunner()


@pytest.mark.parametrize("fixture, needle", [
    ("selinux_avc_name_bind_rhel10.log", "nginx denied {name_bind} on transproxy_port_t"),
    ("selinux_avc_filecontext_rhel10.log", "nginx denied {read} on user_home_t"),
])
def test_enforced_denial_is_reported(fixture, needle, tmp_path):
    log = _copy_to_tmp(fixture, tmp_path)
    out = json.loads(runner.invoke(app, [str(log), "--json", "--no-baseline"]).stdout)
    assert out["level"] == "WARNING"
    assert out["category"] == "config_error"
    assert needle in out["findings"][0]["detail"]
    assert "audit2why" in out["remediation"]


def _ev(msg):
    return ParsedEvent(timestamp=datetime(2026, 10, 13), severity=Severity.WARNING,
                       source="auditd", message=msg, raw=msg, line_number=1)


def test_permissive_denials_are_not_counted():
    rec = ('AVC: avc:  denied  { read } for  pid=1 comm="nginx" name="x" '
           'scontext=system_u:system_r:httpd_t:s0 '
           'tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=FLAG')
    assert analyze_policy_denials([_ev(rec.replace('FLAG', '1'))]) == []
    assert len(analyze_policy_denials([_ev(rec.replace('FLAG', '0'))])) == 1


def test_the_word_denied_alone_is_not_a_policy_denial():
    assert analyze_policy_denials([_ev("access denied for user bob")]) == []
