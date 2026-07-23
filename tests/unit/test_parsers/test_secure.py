import pytest

from logcrux.models import Severity
from logcrux.parsers.secure import SecureParser


@pytest.fixture
def parser():
    return SecureParser()


@pytest.mark.parametrize("line,expected_severity,expected_fragment", [
    (
        "Jun 16 03:41:00 prod-web01 sshd[2001]: Failed password for root "
        "from 198.51.100.42 port 54001 ssh2",
        Severity.WARNING, "Failed password",
    ),
    (
        "Jun 16 09:00:00 prod-web01 sshd[5678]: Accepted publickey for deploy "
        "from 10.0.1.10 port 43210 ssh2",
        Severity.INFO, "Accepted publickey",
    ),
    (
        "Jun 16 03:41:03 prod-web01 sshd[2007]: Invalid user postgres "
        "from 198.51.100.42 port 54006",
        Severity.WARNING, "Invalid user",
    ),
])
def test_parse_valid_auth_lines(parser, line, expected_severity, expected_fragment):
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == expected_severity
    assert expected_fragment in event.message


def test_failed_password_extracts_ip(parser):
    line = (
        "Jun 16 03:41:00 prod-web01 sshd[2001]: Failed password for root "
        "from 198.51.100.42 port 54001 ssh2"
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.extra.get("client_ip") == "198.51.100.42"
    assert event.extra.get("user") == "root"


def test_stream_counts_events(parser, auth_bruteforce_path):
    with open(auth_bruteforce_path, errors="replace") as f:
        events = list(parser.parse_stream(f))
    assert len(events) == 20
    failed = [e for e in events if "Failed" in e.message or "Invalid" in e.message]
    assert len(failed) >= 15


def test_does_not_claim_mixed_syslog():
    # A clean /var/log/syslog with one sshd line among systemd/cron/kernel must
    # NOT be hijacked as an SSH auth log — auth tags must dominate.
    mixed = [
        "Jun 16 09:00:00 prod-web01 sshd[5678]: Accepted publickey for deploy",
        "Jun 16 09:00:05 prod-web01 systemd[1]: Started Session 42 of user deploy.",
        "Jun 16 09:01:00 prod-web01 cron[999]: (root) CMD (/usr/bin/run-parts)",
        "Jun 16 09:05:00 prod-web01 kernel: [234567.000] NET: Registered PF_INET6",
        "Jun 16 09:10:00 prod-web01 sshd[5679]: Disconnected from user deploy",
    ]
    assert SecureParser.can_parse(None, mixed) is False


def test_claims_auth_dominant_log(auth_bruteforce_path):
    sample = auth_bruteforce_path.read_text().splitlines()[:20]
    assert SecureParser.can_parse(None, sample) is True


@pytest.mark.parametrize("ip", ["2001:db8::1", "::1", "::ffff:192.0.2.1", "fe80::1%eth0"])
def test_ipv6_client_ip_extracted(parser, ip):
    line = (
        f"Jun 16 03:41:00 host sshd[1234]: Failed password for root "
        f"from {ip} port 1234 ssh2"
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.extra.get("client_ip") is not None, f"IPv6 {ip} not extracted"
    assert event.severity == Severity.WARNING


def test_iso_timestamp_auth_log_parses(parser):
    line = (
        "2026-06-16T03:41:00+0000 host sshd[1234]: "
        "Failed password for root from 198.51.100.1 port 22 ssh2"
    )
    event = parser.parse_line(line, 1)
    assert event is not None, "ISO-timestamp auth line returned None (all lines dropped)"
    assert event.severity == Severity.WARNING
    assert event.timestamp is not None


def test_iso_timestamp_brute_force_not_clean(parser):
    lines = [
        f"2026-06-16T03:41:0{i}+0000 host sshd[{1000+i}]: "
        f"Failed password for root from 198.51.100.1 port {22000+i} ssh2"
        for i in range(5)
    ]
    events = [parser.parse_line(ln, i) for i, ln in enumerate(lines)]
    assert all(e is not None for e in events), "ISO-format lines silently dropped"
