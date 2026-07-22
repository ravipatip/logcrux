from __future__ import annotations

from datetime import UTC, datetime

from logcrux.analysis.proxy import analyze_proxy_anomalies
from logcrux.models import ParsedEvent, Severity


def _ts():
    return datetime(2026, 6, 16, 3, 41, 0, tzinfo=UTC)


def _squid_event(
    result_code: str = "TCP_MISS",
    status: int = 200,
    method: str = "GET",
    url: str = "http://example.com/",
    connect_port: int | None = None,
) -> ParsedEvent:
    return ParsedEvent(
        timestamp=_ts(),
        severity=Severity.INFO,
        source="squid",
        message=f"{method} {url} {result_code}/{status}",
        raw="raw",
        line_number=1,
        extra={
            "parser": "squid",
            "result_code": result_code,
            "status_code": status,
            "method": method,
            "url": url,
            "connect_port": connect_port,
        },
    )


def _non_squid_event() -> ParsedEvent:
    return ParsedEvent(
        timestamp=_ts(),
        severity=Severity.WARNING,
        source="sshd",
        message="Failed password for root",
        raw="raw",
        line_number=1,
        extra={},
    )


def test_denial_cluster_detected():
    events = [_squid_event("TCP_DENIED", 403) for _ in range(10)]
    signals = analyze_proxy_anomalies(events, failure_threshold=10)
    kinds = [s.kind for s in signals]
    assert "proxy_denial_cluster" in kinds


def test_denial_cluster_below_threshold():
    events = [_squid_event("TCP_DENIED", 403) for _ in range(9)]
    signals = analyze_proxy_anomalies(events, failure_threshold=10)
    assert not any(s.kind == "proxy_denial_cluster" for s in signals)


def test_tunnel_anomaly_port_22():
    events = [_squid_event("TCP_TUNNEL", 200, "CONNECT", "bad.com:22", connect_port=22)]
    signals = analyze_proxy_anomalies(events)
    assert any(s.kind == "tunnel_anomaly" for s in signals)


def test_tunnel_anomaly_port_4444():
    events = [_squid_event("TCP_TUNNEL", 200, "CONNECT", "bad.com:4444", connect_port=4444)]
    signals = analyze_proxy_anomalies(events)
    assert any(s.kind == "tunnel_anomaly" for s in signals)


def test_tunnel_no_anomaly_port_443():
    events = [_squid_event("TCP_TUNNEL", 200, "CONNECT", "secure.com:443", connect_port=443)]
    signals = analyze_proxy_anomalies(events)
    assert not any(s.kind == "tunnel_anomaly" for s in signals)


def test_tunnel_no_anomaly_port_8080():
    events = [_squid_event("TCP_TUNNEL", 200, "CONNECT", "proxy.com:8080", connect_port=8080)]
    signals = analyze_proxy_anomalies(events)
    assert not any(s.kind == "tunnel_anomaly" for s in signals)


def test_auth_407_cluster_detected():
    events = [_squid_event("NONE", 407) for _ in range(10)]
    signals = analyze_proxy_anomalies(events, failure_threshold=10)
    assert any(s.kind == "auth_failure_cluster" for s in signals)


def test_auth_407_below_threshold():
    events = [_squid_event("NONE", 407) for _ in range(9)]
    signals = analyze_proxy_anomalies(events, failure_threshold=10)
    assert not any(s.kind == "auth_failure_cluster" for s in signals)


def test_cache_bypass_spike_detected():
    events = [_squid_event("TCP_MISS", 200) for _ in range(19)]
    events += [_squid_event("TCP_HIT", 200)]
    # 19/20 = 95% TCP_MISS with 20 total → triggers
    signals = analyze_proxy_anomalies(events)
    assert any(s.kind == "error_burst" for s in signals)


def test_cache_bypass_below_ratio():
    events = [_squid_event("TCP_MISS", 200) for _ in range(15)]
    events += [_squid_event("TCP_HIT", 200) for _ in range(10)]
    # 15/25 = 60% TCP_MISS → does not trigger
    signals = analyze_proxy_anomalies(events)
    assert not any(s.kind == "error_burst" for s in signals)


def test_cache_bypass_below_minimum_events():
    events = [_squid_event("TCP_MISS", 200) for _ in range(19)]
    # 19/19 = 100% TCP_MISS but total < 20 → does not trigger
    signals = analyze_proxy_anomalies(events)
    assert not any(s.kind == "error_burst" for s in signals)


def test_non_squid_events_ignored():
    events = [_non_squid_event() for _ in range(20)]
    signals = analyze_proxy_anomalies(events)
    assert signals == []


def test_empty_events_returns_empty():
    assert analyze_proxy_anomalies([]) == []


def test_denial_signal_has_correct_event_count():
    events = [_squid_event("TCP_DENIED", 403) for _ in range(12)]
    signals = analyze_proxy_anomalies(events, failure_threshold=10)
    denial = next(s for s in signals if s.kind == "proxy_denial_cluster")
    assert denial.event_count == 12


# --- Firewall block clusters (UFW/pfSense/firewalld drop floods) ---

def _ufw_block_event(second: int = 0) -> ParsedEvent:
    from datetime import timedelta

    return ParsedEvent(
        timestamp=_ts() + timedelta(seconds=second),
        severity=Severity.WARNING,
        source="ufw",
        message="UFW BLOCK TCP 198.51.100.77 -> 10.0.1.5:22",
        raw="raw",
        line_number=1,
        extra={"action": "BLOCK", "src_ip": "198.51.100.77"},
    )


def test_firewall_block_cluster_detected():
    # 30 blocks within one minute → concentrated flood
    events = [_ufw_block_event(i * 2) for i in range(30)]
    signals = analyze_proxy_anomalies(events, failure_threshold=10)
    assert any(s.kind == "firewall_block_cluster" for s in signals)


def test_firewall_blocks_spread_thin_not_flagged():
    # 30 blocks spread over 25 hours → background noise, not an incident
    from datetime import timedelta

    events = [
        _ufw_block_event(0).model_copy(update={"timestamp": _ts() + timedelta(hours=i)})
        for i in range(30)
    ]
    signals = analyze_proxy_anomalies(events, failure_threshold=10)
    assert not any(s.kind == "firewall_block_cluster" for s in signals)


def test_firewall_allow_events_not_counted():
    events = [
        _ufw_block_event(i).model_copy(update={"extra": {"action": "ALLOW"}})
        for i in range(30)
    ]
    signals = analyze_proxy_anomalies(events, failure_threshold=10)
    assert not any(s.kind == "firewall_block_cluster" for s in signals)
