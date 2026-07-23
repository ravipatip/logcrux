from datetime import UTC, datetime

import pytest

from logcrux.models import Finding, IncidentCategory, IncidentSummary
from logcrux.state.db import Database
from logcrux.state.history import get_recent_runs, insert_run


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "test.db")


def _summary() -> IncidentSummary:
    return IncidentSummary(
        level="WARNING",
        title="SSH brute force",
        findings=[Finding(headline="847 failed logins")],
        confidence=0.96,
        category=IncidentCategory.AUTH_BRUTE_FORCE,
        log_path="/var/log/secure",
        analyzed_at=datetime.now(UTC),
        parsed_count=1000,
        elapsed_seconds=2.1,
    )


def test_insert_and_retrieve(db):
    summary = _summary()
    insert_run(db, summary)
    runs = get_recent_runs(db, "/var/log/secure", limit=10)
    assert len(runs) == 1
    assert runs[0]["incident_level"] == "WARNING"


def test_multiple_runs_ordered_by_time(db):
    for _ in range(3):
        insert_run(db, _summary())
    runs = get_recent_runs(db, "/var/log/secure", limit=10)
    assert len(runs) == 3
