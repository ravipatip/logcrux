from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.postfix import PostfixParser


@pytest.fixture
def parser():
    return PostfixParser()


_SENT = "Jun 19 10:00:05 mail01 postfix/smtp[9012]: ABC123DEF456: to=<recipient@example.org>, relay=mx.example.org[5.6.7.8]:25, delay=0.74, delays=0.06/0.01/0.25/0.42, dsn=2.0.0, status=sent (250 ok dirdel)"
_BOUNCED = "Jun 19 10:00:06 mail01 postfix/smtp[9013]: DEF456GHI789: to=<user@bounced.com>, relay=mx.bounced.com[9.10.11.12]:25, delay=5.2, delays=0.1/0.2/4.8/0.1, dsn=5.1.1, status=bounced (host mx.bounced.com said: 550 User unknown)"
_AUTH_FAIL = "Jun 19 10:00:02 mail01 postfix/smtpd[1234]: warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: authentication failure"
_REJECT = "Jun 19 10:00:03 mail01 postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 550 5.1.1"
_SENDER = "Jun 19 10:00:04 mail01 postfix/qmgr[5678]: ABC123DEF456: from=<user@example.com>, size=2048, nrcpt=1 (queue active)"


def test_parse_sent(parser):
    event = parser.parse_line(_SENT, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["delivery_status"] == "sent"
    assert event.extra["to"] == "recipient@example.org"
    assert event.source == "postfix"


def test_parse_bounced_is_warning(parser):
    event = parser.parse_line(_BOUNCED, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["delivery_status"] == "bounced"


def test_parse_sasl_failure_is_warning(parser):
    event = parser.parse_line(_AUTH_FAIL, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_parse_reject_is_warning(parser):
    event = parser.parse_line(_REJECT, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_parse_sender_extracts_from(parser):
    event = parser.parse_line(_SENDER, 1)
    assert event is not None
    assert event.extra["from"] == "user@example.com"
    assert event.extra["size"] == 2048


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_can_parse_by_path_mail_log():
    assert PostfixParser.can_parse(Path("/var/log/mail.log"), [])


def test_can_parse_by_path_maillog():
    assert PostfixParser.can_parse(Path("/var/log/maillog"), [])


def test_can_parse_by_content():
    assert PostfixParser.can_parse(None, [_SENT])


def test_fixture(parser):
    fixture = Path("tests/fixtures/postfix.log")
    with open(fixture) as f:
        events = list(parser.parse_stream(f))
    assert len(events) >= 4
    warnings = [e for e in events if e.severity == Severity.WARNING]
    assert len(warnings) >= 2


@pytest.mark.parametrize("queue_id,line_suffix", [
    # Postfix 3.5+ long mixed-case queue IDs
    ("ZsB2kgqR9zpD08Cv6g", "ZsB2kgqR9zpD08Cv6g: from=<sender@example.com>, size=1024, nrcpt=1"),
    # lowercase hex (classic format, all lowercase)
    ("3abc1f2d4e5a", "3abc1f2d4e5a: from=<sender@example.com>, size=512, nrcpt=1"),
])
def test_modern_postfix_queue_ids(parser, queue_id, line_suffix):
    line = f"Jun 19 10:00:04 mail01 postfix/qmgr[5678]: {line_suffix}"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.extra.get("queue_id") == queue_id, (
        f"queue_id not extracted for {queue_id!r}: got {event.extra.get('queue_id')!r}"
    )


def test_postfix_script_fatal_line(parser):
    line = "Jun 16 10:00:03 mail postfix-script: fatal: Usage: postfix start"
    event = parser.parse_line(line, 1)
    assert event is not None, "postfix-script line returned None"
    assert event.severity == Severity.ERROR


def test_postfix_script_detected_by_content():
    line = "Jun 16 10:00:03 mail postfix-script: fatal: Usage: postfix start"
    assert PostfixParser.can_parse(None, [line])
