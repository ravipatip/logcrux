import pytest

from logcrux.models import Severity
from logcrux.parsers.json_access import JsonAccessParser
from logcrux.parsers.registry import detect_parser


@pytest.fixture
def parser():
    return JsonAccessParser()


def test_parse_200_info(parser):
    line = (
        '{"time_local": "16/Jun/2026:03:41:00 +0000", "remote_addr": "10.0.1.50", '
        '"request": "GET /index.html HTTP/1.1", "status": 200, "body_bytes_sent": 1234}'
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["status_code"] == 200
    assert event.extra["method"] == "GET"
    assert event.extra["path"] == "/index.html"
    assert event.extra["client_ip"] == "10.0.1.50"
    assert event.timestamp is not None


def test_parse_500_is_error(parser):
    line = '{"time": "16/Jun/2026:03:41:04 +0000", "request": "GET /api HTTP/1.1", "response": 500}'
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.ERROR  # 5xx → ERROR drives error-burst detection


def test_parse_404_is_warning(parser):
    line = '{"request": "GET /missing HTTP/1.1", "status": 404}'
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_rejects_non_access_json(parser):
    # An app JSON logger (no METHOD/path request + status) must not be claimed.
    assert parser.parse_line('{"level": "info", "msg": "started", "v": 0}', 1) is None
    assert parser.parse_line('{"request": "do thing", "status": "ok"}', 1) is None
    assert parser.parse_line("not json at all", 1) is None


def test_stream_fixture(parser, fixtures_dir):
    with open(fixtures_dir / "json_access.log", errors="replace") as f:
        events = list(parser.parse_stream(f))
    assert len(events) == 5
    assert all(e.timestamp is not None for e in events)
    # 502 + 500 → ERROR
    assert sum(1 for e in events if e.severity == Severity.ERROR) == 2


def test_registry_detects_json_access(fixtures_dir):
    lines = (fixtures_dir / "json_access.log").read_text().splitlines()
    parser = detect_parser(fixtures_dir / "json_access.log", lines[:5])
    assert parser.FORMAT_NAME == "json-access"


def test_json_access_not_hijacking_app_json(fixtures_dir):
    # A neighbouring JSON app-logger fixture must keep its own parser.
    for name in ("pino.log", "bunyan.log", "gcp.log"):
        path = fixtures_dir / name
        if not path.exists():
            continue
        lines = path.read_text(errors="replace").splitlines()
        parser = detect_parser(path, lines[:5])
        assert parser.FORMAT_NAME != "json-access", name
