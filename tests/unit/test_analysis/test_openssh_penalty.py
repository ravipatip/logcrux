"""OpenSSH PerSourcePenalties lines — real Debian 13 / OpenSSH 10.0 (GCP, 2026-10-13)."""
from logcrux.analysis.anomaly import _is_auth_failure
from logcrux.parsers.syslog import SyslogParser

PENALTY = """Oct 13 03:38:56 lc-debian-13 sshd[960]: drop connection #0 from [127.0.0.1]:51354 on [127.0.0.1]:22 penalty: failed authentication"""
SCANNER = """Oct 13 03:31:52 lc-rhel-10 sshd[2598]: drop connection #0 from [127.0.0.1]:49450 on [127.0.0.1]:22 penalty: connections without attempting authentication"""


def _ev(line):
    return SyslogParser().parse_line(line, 1)


def test_failed_authentication_penalty_counts_as_auth_failure():
    assert _is_auth_failure(_ev(PENALTY))


def test_no_attempt_penalty_is_not_password_guessing():
    assert not _is_auth_failure(_ev(SCANNER))
