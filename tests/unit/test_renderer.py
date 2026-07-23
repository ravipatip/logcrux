import json
from datetime import UTC, datetime
from io import StringIO

import pytest
from rich.console import Console

from logcrux.models import Finding, IncidentCategory, IncidentSummary
from logcrux.output.renderer import render_json, render_summary


def _summary(level: str, title: str = "Test incident") -> IncidentSummary:
    return IncidentSummary(
        level=level,  # type: ignore[arg-type]
        title=title,
        findings=[Finding(headline="Test finding", detail="10 events in 60s")],
        confidence=0.94,
        category=IncidentCategory.AUTH_BRUTE_FORCE,
        remediation="Block the IP",
        log_path="/var/log/secure",
        analyzed_at=datetime.now(UTC),
        parsed_count=1000,
        elapsed_seconds=2.1,
    )


@pytest.fixture
def console_and_buf():
    buf = StringIO()
    con = Console(file=buf, highlight=False, color_system=None)
    return con, buf


def test_render_critical_contains_title(console_and_buf):
    con, buf = console_and_buf
    render_summary(_summary("CRITICAL"), con)
    output = buf.getvalue()
    assert "Test incident" in output
    assert "CRITICAL" in output


def test_render_clean_shows_clean(console_and_buf):
    con, buf = console_and_buf
    clean = IncidentSummary(
        level="CLEAN", title="No incidents detected", findings=[],
        confidence=1.0, category=IncidentCategory.UNKNOWN,
        log_path="/var/log/messages",
        analyzed_at=datetime.now(UTC),
        parsed_count=500, elapsed_seconds=0.8,
    )
    render_summary(clean, con)
    assert "CLEAN" in buf.getvalue()


def test_remediation_shown_by_default(console_and_buf):
    con, buf = console_and_buf
    render_summary(_summary("CRITICAL"), con)
    assert "Block the IP" in buf.getvalue()


def test_remediation_hidden_when_disabled(console_and_buf):
    con, buf = console_and_buf
    render_summary(_summary("CRITICAL"), con, show_remediation=False)
    out = buf.getvalue()
    assert "Block the IP" not in out
    assert "Remediation" not in out


def test_render_json_is_valid(console_and_buf):
    con, buf = console_and_buf
    render_json(_summary("WARNING"), con)
    data = json.loads(buf.getvalue())
    assert data["level"] == "WARNING"
    assert data["confidence"] == pytest.approx(0.94)
    assert "findings" in data
