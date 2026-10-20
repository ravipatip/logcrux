"""On-prem middleware and backup tier — lab/apps3, the third held-out round
(real containers, 2026-10-20). Scored before these fixes: 3/7 faults; kopia
had no parser, Tomcat's stack traces sank its parser to generic."""
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from logcrux.cli import app
from logcrux.parsers.registry import detect_parser

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _run(name: str) -> dict[str, Any]:
    r = CliRunner().invoke(app, [str(FIXTURES / name), "--no-baseline", "--json"])
    data: dict[str, Any] = json.loads(r.output)
    return data


@pytest.mark.parametrize("name,detail", [
    ("kopia_badpass.log", "invalid repository password"),
    ("kopia_missing_src.log", "no such file or directory"),
    ("kopia_repo_gone.log", "cannot access storage path"),
])
def test_kopia_failures_are_job_failures(name, detail):
    data = _run(name)
    assert data["parser_format"] == "kopia"
    f = data["findings"][0]
    assert f["kind"] == "job_failure" and detail in f["detail"]


def test_kopia_clean_snapshot_is_clean():
    data = _run("kopia_ok.log")
    assert data["parser_format"] == "kopia" and data["level"] == "CLEAN"


def test_kopia_gate_is_not_a_bare_error_prefix():
    plain = ["ERROR something went wrong in my app", "INFO retrying"]
    assert detect_parser(None, plain).FORMAT_NAME != "kopia"


def test_tomcat_startup_config_failure():
    data = _run("tomcat_badconfig_docker.log")
    assert data["parser_format"] == "tomcat"
    assert data["category"] == "config_error"
    assert any("Parse fatal error at line [163]" in e["text"]
               for e in data["findings"][0]["evidence"])


def test_tomcat_servlet_oom_in_localhost_log():
    data = _run("tomcat_oom_localhost.log")
    assert data["parser_format"] == "tomcat" and data["category"] == "oom"


def test_kafka_startup_configexception_is_a_config_error():
    data = _run("kafka_configexception_docker.log")
    assert data["category"] == "config_error"
    assert data["findings"][0]["kind"] == "uncaught_exception"


@pytest.mark.parametrize("name,kind,subject", [
    # lab/apps4, the fourth held-out round: 0/3 detected before these.
    ("phpfpm_fatal_docker.log", "service_crash", ("script", "/var/www/html/broken.php")),
    ("keycloak_authfail_docker.log", "auth_failure_cluster", ("user", "admin")),
    ("openldap_authfail_docker.log", "auth_failure_cluster", None),
])
def test_php_keycloak_ldap_failures(name, kind, subject):
    data = _run(name)
    f = data["findings"][0]
    assert data["level"] in ("WARNING", "CRITICAL") and f["kind"] == kind
    if subject:
        assert subject in {(s["label"], s["value"]) for s in f["subjects"]}


def test_keycloak_healthy_start_is_clean():
    assert _run("keycloak_ok_docker.log")["level"] == "CLEAN"


@pytest.mark.parametrize("name,category", [
    # lab/apps5, the fifth held-out round: prometheus and mosquitto were CLEAN.
    ("prometheus_badconfig_docker.log", "config_error"),
    ("mosquitto_authfail_docker.log", "auth_brute_force"),
    ("envoy_503_uf_docker.log", "http_overload"),
    ("coredns_upstream_timeout_docker.log", "network_issue"),
])
def test_infrastructure_services(name, category):
    data = _run(name)
    assert data["level"] in ("WARNING", "CRITICAL") and data["category"] == category, data["title"]
