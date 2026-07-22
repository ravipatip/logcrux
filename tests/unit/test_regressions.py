"""Regression tests for bugs fixed during the codebase audit."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from logcrux.analysis.engine import run_analysis
from logcrux.cli import _filter_last
from logcrux.config import AnalysisConfig
from logcrux.models import ParsedEvent, Severity


def _ev(ts, sev=Severity.INFO, msg="msg", line=1):
    return ParsedEvent(
        timestamp=ts, severity=sev, source="src", message=msg, raw="raw", line_number=line
    )


class TestFilterLast:
    """--last previously parsed raw lines and silently kept everything when the
    timestamp prefix contained trailing tokens (e.g. syslog). It now filters on
    parser-extracted timestamps."""

    def test_drops_events_older_than_window(self):
        now = datetime.now(UTC)
        old = _ev(now - timedelta(hours=5))
        recent = _ev(now - timedelta(minutes=1))
        kept = _filter_last([old, recent], timedelta(hours=1))
        assert kept == [recent]

    def test_keeps_all_when_window_large(self):
        now = datetime.now(UTC)
        events = [_ev(now - timedelta(minutes=i)) for i in range(5)]
        assert len(_filter_last(events, timedelta(days=1))) == 5

    def test_keeps_untimed_events(self):
        now = datetime.now(UTC)
        untimed = _ev(None)
        recent = _ev(now)
        kept = _filter_last([untimed, recent], timedelta(hours=1))
        assert untimed in kept and recent in kept

    def test_naive_timestamps_treated_as_utc(self):
        # Naive (syslog-style) timestamps must still be comparable, not crash.
        naive_old = _ev(datetime(2000, 1, 1, 0, 0, 0))
        kept = _filter_last([naive_old], timedelta(hours=1))
        assert kept == []


class TestMixedTzCorrelation:
    """run_analysis crashed with 'can't compare offset-naive and offset-aware'
    when one signal came from untimed events (aware fallback window) and another
    from timed events (naive window)."""

    def test_untimed_plus_timed_signals_does_not_crash(self):
        events = [
            _ev(None, sev=Severity.WARNING, msg="Failed password for root", line=i)
            for i in range(12)
        ]
        events.append(
            _ev(datetime(2026, 6, 19, 10, 0, 0), sev=Severity.CRITICAL,
                msg="Out of memory: killed process", line=99)
        )
        result = run_analysis(
            events, "syslog", "/tmp/x.log", baseline=None, config=AnalysisConfig()
        )
        kinds = {s.kind for s in result.signals}
        assert "auth_failure_cluster" in kinds
        assert "oom_event" in kinds


class TestRedisOldFormatTimestamp:
    """The Redis 2.x/3.x parser injected the year between day and month and
    dropped the clock entirely (`"01 Jan 12:34:56"` -> `"01 2026 Jan"`), so every
    old-format event landed at midnight. The day/month/time order is now kept."""

    def test_old_format_preserves_time(self):
        from logcrux.parsers.redis import RedisParser

        ev = RedisParser().parse_line(
            "[1234] 01 Jan 12:34:56.789 * Background saving started", 1
        )
        assert ev is not None
        assert ev.timestamp is not None
        assert (ev.timestamp.hour, ev.timestamp.minute, ev.timestamp.second) == (12, 34, 56)


class TestHAProxyTcpTermination:
    """The TCP-mode severity check compared the (uppercase) termination state
    against a lowercase 'c', so a client-aborted connection ('CD') was flagged
    WARNING in TCP mode while the HTTP path correctly treated 'C' as benign."""

    def test_client_abort_not_flagged(self):
        from logcrux.parsers.haproxy import HAProxyParser

        line = (
            "Jun 19 10:00:05 lb haproxy[123]: 10.0.1.9:54321 "
            "[19/Jun/2026:10:00:05.345] tcp-in db-backend/db1 5/10/3000 9876 CD"
        )
        ev = HAProxyParser().parse_line(line, 1)
        assert ev is not None
        assert ev.severity == Severity.INFO
