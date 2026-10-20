"""What a Kubernetes user pipes into logcrux — real k3s 1.31 captures (lab/k8s,
2026-10-20). Measured before the fixes: 4/6 faults detected; the image-pull
failure and the crashed container's own last words were CLEAN."""
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from logcrux.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent.parent / "fixtures"


def _run(name: str) -> dict[str, Any]:
    result = runner.invoke(app, [str(FIXTURES / name), "--no-baseline", "--json"])
    assert result.exit_code in (0, 3, 4), result.output
    data: dict[str, Any] = json.loads(result.output)
    return data


@pytest.mark.parametrize("name,category,kind", [
    ("k8s_describe_imagepull_k3s.log", "config_error", "config_error"),
    ("k8s_describe_oomkilled_k3s.log", "oom", "oom_event"),
    ("k8s_get_events_k3s.log", "config_error", "config_error"),
])
def test_k8s_capture(name, category, kind):
    data = _run(name)
    assert data["level"] in ("WARNING", "CRITICAL")
    if category:
        assert data["category"] == category
    assert data["findings"][0]["kind"] == kind


def test_image_pull_names_image_and_pod():
    f = _run("k8s_get_events_k3s.log")["findings"][0]
    subs = {(s["label"], s["value"]) for s in f["subjects"]}
    assert ("image", "busybox:1.36-doesnotexist") in subs and ("pod", "typo-image") in subs


def test_crashed_pods_are_named():
    data = _run("k8s_get_events_k3s.log")
    crash = next(f for f in data["findings"] if f["kind"] == "service_crash")
    assert {s["value"] for s in crash["subjects"]} >= {"crashy-api", "hungry-worker"}


def test_healthy_pod_with_kubectl_timestamps_is_clean():
    data = _run("k8s_logs_healthy_timestamps.log")
    assert data["level"] == "CLEAN" and data["parsed_count"] > 50


def test_final_error_only_for_short_inputs():
    from logcrux.analysis.anomaly import final_error_event as analyze_final_error
    from logcrux.models import ParsedEvent, Severity

    def ev(i, sev):
        msg = f"m{i}: cannot connect to db"
        return ParsedEvent(timestamp=None, severity=sev, source="x", message=msg,
                           raw=msg, line_number=i)
    assert analyze_final_error([ev(1, Severity.INFO), ev(2, Severity.ERROR)])
    assert not analyze_final_error([ev(1, Severity.ERROR), ev(2, Severity.INFO)])
    long = [ev(i, Severity.INFO) for i in range(1, 400)] + [ev(400, Severity.ERROR)]
    assert not analyze_final_error(long)


def test_crashed_container_last_words_are_shown_not_alarmed():
    data = _run("k8s_logs_previous_final_error.log")
    assert data["level"] == "CLEAN"
    assert "cannot connect to postgres" in data["last_error"]["text"]
    result = runner.invoke(app, [str(FIXTURES / "k8s_logs_previous_final_error.log"),
                                 "--no-baseline"])
    assert "Last line logged is an error (line 2)" in result.output


def test_scheduling_and_probe_failures():
    # lab/k8s2 (real k3s): 0/4 detected before these rules.
    sched = _run("k8s_describe_failedscheduling_k3s.log")["findings"][0]
    assert sched["kind"] == "resource_limit"
    assert ("limit", "cluster capacity") in {(s["label"], s["value"]) for s in sched["subjects"]}
    live = _run("k8s_describe_liveness_k3s.log")
    assert any(f["kind"] == "probe_failure" for f in live["findings"])
    ev = _run("k8s_events_sched_probes_k3s.log")
    assert {f["kind"] for f in ev["findings"]} >= {"resource_limit", "probe_failure"}


def test_one_readiness_failure_at_startup_is_normal():
    from logcrux.analysis.anomaly import analyze_probe_failures
    from logcrux.models import ParsedEvent, Severity
    e = ParsedEvent(timestamp=None, severity=Severity.WARNING, source="k", raw="",
                    message="Warning Unhealthy pod/web Readiness probe failed: HTTP 503",
                    line_number=1)
    assert analyze_probe_failures([e]) == []
