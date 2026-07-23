import pytest

from logcrux.state.baseline import get_baseline, upsert_baseline
from logcrux.state.db import Database


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "test.db")


def test_get_baseline_missing_returns_none(db):
    assert get_baseline(db, "/var/log/messages") is None


def test_upsert_and_retrieve(db):
    upsert_baseline(db, "/var/log/messages", "syslog",
                    avg_events_per_hour=100.0, avg_errors_per_hour=2.0,
                    p95_burst_size=10.0)
    record = get_baseline(db, "/var/log/messages")
    assert record is not None
    assert record.avg_errors_per_hour == pytest.approx(2.0)
    assert record.parser_format == "syslog"


def test_upsert_applies_ema(db):
    upsert_baseline(db, "/var/log/test.log", "generic",
                    avg_events_per_hour=100.0, avg_errors_per_hour=10.0,
                    p95_burst_size=20.0)
    upsert_baseline(db, "/var/log/test.log", "generic",
                    avg_events_per_hour=200.0, avg_errors_per_hour=5.0,
                    p95_burst_size=15.0, alpha=0.5)
    record = get_baseline(db, "/var/log/test.log")
    assert record is not None
    # EMA applies to every tracked rate, not just errors: alpha*new + (1-alpha)*old
    assert record.avg_errors_per_hour == pytest.approx(7.5)  # 0.5*5 + 0.5*10
    assert record.avg_events_per_hour == pytest.approx(150.0)  # 0.5*200 + 0.5*100
    assert record.p95_burst_size == pytest.approx(17.5)  # 0.5*15 + 0.5*20
