from datetime import UTC, datetime, timedelta

from logcrux.analysis.engine import run_analysis
from logcrux.config import AnalysisConfig
from logcrux.models import ParsedEvent, Severity


def _ev(minutes: int, sev: Severity, source: str = "sshd",
        msg: str = "Failed password for root from 192.0.2.1 port 1 ssh2") -> ParsedEvent:
    ts = datetime(2026, 6, 16, 3, 41, 0, tzinfo=UTC) + timedelta(minutes=minutes)
    return ParsedEvent(timestamp=ts, severity=sev, source=source,
                       message=msg, raw="raw", line_number=1,
                       extra={"client_ip": "192.0.2.1", "user": "root"})


def test_clean_log_returns_no_signals():
    events = [_ev(i, Severity.INFO, msg="normal log line") for i in range(20)]
    result = run_analysis(events, "test", "/var/log/test.log",
                          baseline=None, config=AnalysisConfig())
    assert result.signals == []


def test_auth_failures_generate_signal():
    events = [_ev(i % 5, Severity.WARNING) for i in range(60)]
    result = run_analysis(events, "secure", "/var/log/secure",
                          baseline=None,
                          config=AnalysisConfig(auth_failure_threshold=50))
    signal_kinds = [s.kind for s in result.signals]
    assert "auth_failure_cluster" in signal_kinds


def test_result_counts_match_inputs():
    events = [_ev(i, Severity.INFO, msg="info msg") for i in range(10)]
    result = run_analysis(events, "syslog", "/var/log/messages",
                          baseline=None, config=AnalysisConfig())
    assert result.parsed_count == 10
    assert result.skipped_count == 0
