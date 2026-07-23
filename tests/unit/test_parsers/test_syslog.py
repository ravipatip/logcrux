
import pytest

from logcrux.models import Severity
from logcrux.parsers.syslog import SyslogParser


@pytest.fixture
def parser():
    return SyslogParser()


@pytest.mark.parametrize("line,expected_source,expected_severity,expected_msg_fragment", [
    (
        "Jun 16 03:42:00 prod-web01 kernel: Out of memory: Kill process 12345",
        "kernel", Severity.CRITICAL, "Out of memory",
    ),
    (
        "Jun 16 09:00:00 prod-web01 sshd[5678]: Accepted publickey for deploy",
        "sshd", Severity.INFO, "Accepted publickey",
    ),
    (
        "Jun 16 09:01:00 prod-web01 cron[999]: (root) CMD (/usr/bin/run-parts /etc/cron.hourly)",
        "cron", Severity.INFO, "CMD",
    ),
    (
        "Jun  5 03:42:00 prod-web01 systemd[1]: Failed to start Application.",
        "systemd", Severity.ERROR, "Failed to start",
    ),
])
def test_parse_valid_lines(parser, line, expected_source, expected_severity, expected_msg_fragment):
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.source == expected_source
    assert event.severity == expected_severity
    assert expected_msg_fragment in event.message
    assert event.raw == line


@pytest.mark.parametrize("line", [
    "Jun 20 10:00:00 host app[1]: user joined zoom meeting room now",
    "Jun 20 10:00:01 host app[2]: cleaning the broom closet",
    "Jun 20 10:00:02 host app[3]: bandwidth zoom completed bloom report",
])
def test_oom_substring_does_not_false_flag_critical(parser, line):
    # Regression: a bare "oom" substring used to mark words like "room"/"zoom"
    # as CRITICAL, inflating error counts and triggering spurious incidents.
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity != Severity.CRITICAL


@pytest.mark.parametrize("line", [
    "Jun 16 03:41:55 host kernel: oom-kill:constraint=CONSTRAINT_NONE task=java",
    "Jun 16 03:42:01 host kernel: oom_reaper: reaped process 12345 (java)",
    "Jun 16 03:42:02 host kernel: oom-killer invoked by java",
    "Jun 16 03:42:00 host kernel: Out of memory: Killed process 12345",
])
def test_real_oom_events_are_critical(parser, line):
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.CRITICAL


@pytest.mark.parametrize("line,src,sev,frag", [
    # `journalctl -o short-iso`: ISO timestamp + host + tag, RFC3164 body.
    (
        "2026-06-29T08:41:02+0000 ip-10-0-1-23 kernel: Out of memory: Killed process 4521",
        "kernel", Severity.CRITICAL, "Out of memory",
    ),
    # short-iso-precise (microseconds) + offset with colon, with a PID.
    (
        "2026-06-29T08:41:04.123456+00:00 host systemd[1]: Failed with result 'signal'.",
        "systemd", Severity.ERROR, "Failed with result",
    ),
    # UTC 'Z' suffix.
    (
        "2026-06-29T08:40:14Z host sshd[42]: Accepted publickey for deploy",
        "sshd", Severity.INFO, "Accepted publickey",
    ),
])
def test_parse_journalctl_iso_lines(parser, line, src, sev, frag):
    # `journalctl -o short-iso` captures must be claimed by syslog (not generic):
    # the source is stripped, message is clean, and the ISO timestamp parses.
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.source == src
    assert event.severity == sev
    assert frag in event.message
    assert not event.message.startswith("2026-")  # ts/host prefix stripped
    assert event.timestamp is not None


def test_iso_line_preserves_pid(parser):
    event = parser.parse_line(
        "2026-06-29T08:41:04+0000 host systemd[1]: docker.service: start", 1
    )
    assert event is not None
    assert event.extra.get("pid") == "1"


def test_parse_malformed_returns_none(parser):
    assert parser.parse_line("this is not syslog at all", 1) is None


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_parse_preserves_pid_in_extra(parser):
    event = parser.parse_line(
        "Jun 16 03:42:00 prod-web01 sshd[1234]: message", 1
    )
    assert event is not None
    assert event.extra.get("pid") == "1234"


def test_stream_skips_malformed(parser, syslog_oom_path):
    with open(syslog_oom_path, errors="replace") as f:
        events = list(parser.parse_stream(f))
    assert len(events) >= 3
    assert all(e.timestamp is not None for e in events)
