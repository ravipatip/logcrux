"""Per-event memory — one ParsedEvent exists per log line, so per-instance
overhead is the dominant cost on a large log. On a real 510k-line (43 MB)
nginx access log these two changes took peak RSS from 1485 MB to 705 MB.
"""
from datetime import UTC, datetime

from logcrux.analysis.engine import _strip_tzinfo
from logcrux.models import ParsedEvent, Severity


def _ev(ts):
    return ParsedEvent(timestamp=ts, severity=Severity.INFO, source="s",
                       message="m", raw="r", line_number=1)


def test_events_share_one_fields_set():
    a, b = _ev(None), _ev(None)
    assert a.__pydantic_fields_set__ is b.__pydantic_fields_set__
    assert a.model_fields_set == set(ParsedEvent.model_fields)


def test_assignment_still_works_with_the_shared_set():
    a = _ev(None)
    a.timestamp = datetime(2026, 10, 13)
    assert a.timestamp == datetime(2026, 10, 13)


def test_strip_tzinfo_normalises_in_place_without_copying():
    events = [_ev(datetime(2026, 10, 13, tzinfo=UTC)), _ev(None)]
    ids = [id(e) for e in events]
    out = _strip_tzinfo(events)
    assert [id(e) for e in out] == ids
    assert out[0].timestamp.tzinfo is None
