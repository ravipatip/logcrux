"""restic — the registry's first backup/data-protection parser.

Every line asserted here was captured from a real restic/restic container
driving a minio S3 backend, with the fault induced deliberately (the project's
backup lab). The fixtures are that capture, host-anonymised.
"""

from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.registry import detect_parser
from logcrux.parsers.restic import ResticParser


@pytest.fixture
def parser():
    return ResticParser()


def test_snapshot_saved_is_the_success_signal(parser):
    event = parser.parse_line("snapshot b252f12f saved", 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "restic"
    assert event.extra["snapshot_id"] == "b252f12f"
    assert event.extra["outcome"] == "saved"


def test_plain_output_has_no_timestamp(parser):
    """restic is a CLI: its plain output carries no clock at all."""
    event = parser.parse_line("snapshot b252f12f saved", 1)
    assert event is not None and event.timestamp is None


def test_snapshot_table_row_does_carry_a_timestamp(parser):
    event = parser.parse_line(
        "c8b4b798  2026-07-28 04:45:35  labhost              /data  0 B", 1
    )
    assert event is not None
    assert event.timestamp is not None
    assert event.extra["snapshot_id"] == "c8b4b798"
    assert event.extra["host"] == "labhost"


def test_fatal_is_critical_because_no_backup_happened(parser):
    event = parser.parse_line("Fatal: wrong password or no key found", 1)
    assert event is not None
    assert event.severity == Severity.CRITICAL
    assert event.extra["outcome"] == "aborted"


def test_save_error_is_error_not_fatal(parser):
    event = parser.parse_line(
        "error: failed to save /data/blob.bin: read /data/blob.bin: input/output error", 1
    )
    assert event is not None and event.severity == Severity.ERROR


def test_backend_retry_extracts_delay(parser):
    event = parser.parse_line(
        'Stat(<config/>) returned error, retrying after 1.117876261s: Stat: Get '
        '"http://minio:9000/restic/?location=": dial tcp: lookup minio: no such host',
        1,
    )
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["backend_retry"] is True
    assert event.extra["retry_after"] == "1.117876261s"
    assert event.extra["operation"] == "Stat"


def test_retry_recovery_is_distinguishable_from_the_storm(parser):
    """A log that recovered must not look like one still retrying."""
    event = parser.parse_line("Stat(<config/>) operation successful after 1 retries", 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["recovered_after_retries"] == 1


def test_interrupted_run_is_a_warning(parser):
    event = parser.parse_line("signal terminated received, cleaning up ", 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["outcome"] == "interrupted"


def test_missing_source_path_is_a_warning(parser):
    event = parser.parse_line("/seed/missing-dir does not exist, skipping", 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["skipped_path"] == "/seed/missing-dir"


def test_check_verdict_is_flagged(parser):
    event = parser.parse_line("no errors were found", 1)
    assert event is not None and event.extra["verified"] is True


def test_file_counts_are_extracted(parser):
    event = parser.parse_line("Files:           3 new,     0 changed,     0 unmodified", 1)
    assert event is not None
    assert event.extra["files_new"] == 3
    assert event.extra["files_unmodified"] == 0


def test_json_summary(parser):
    line = (
        '{"message_type":"summary","files_new":0,"files_changed":0,'
        '"files_unmodified":3,"data_added":0,"total_files_processed":3,'
        '"total_bytes_processed":490021,"backup_end":"2026-07-28T04:46:23.155505257Z",'
        '"snapshot_id":"b8216b42a966eb62e819d96c58ee3534031d322f87bb824e66de466e3ee24c75"}'
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.extra["message_type"] == "summary"
    assert event.extra["total_files_processed"] == 3
    assert event.timestamp is not None  # summary is the one JSON frame with a clock


def test_json_error_is_error(parser):
    event = parser.parse_line(
        '{"message_type":"error","error":{"message":"read /data/x: input/output error"},'
        '"during":"archival","item":"/data/x"}',
        1,
    )
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.extra["during"] == "archival"


def test_fatal_folds_the_repository_location(parser):
    lines = [
        "Fatal: repository does not exist: unable to open config file: Stat: ...",
        "Is there a repository at the following location?",
        "s3:http://minio:9000/restic",
    ]
    events = list(parser.parse_stream(lines))
    assert len(events) == 1
    assert "s3:http://minio:9000/restic" in events[0].message


def test_table_furniture_is_meta_not_unparsed(parser):
    lines = [
        "ID        Time                 Host          Tags        Paths  Size",
        "-" * 75,
        "Timestamps shown in UTC",
        "2 snapshots",
    ]
    assert list(parser.parse_stream(lines)) == []
    assert parser.meta_lines == 4


def test_does_not_claim_an_unrelated_log():
    assert not ResticParser.can_parse(
        None, ["Jun 20 10:15:01 host sshd[1]: Accepted password for alice"]
    )
    # A cron log that merely mentions backups is not a restic log.
    assert not ResticParser.can_parse(None, ["backup job started", "backup job finished"])


def test_fixture_detects_and_is_fully_accounted_for(fixtures_dir):
    path = fixtures_dir / "restic.log"
    lines = path.read_text().splitlines()
    assert detect_parser(path, lines[:40]).FORMAT_NAME == "restic"
    parser = ResticParser()
    events = list(parser.parse_stream(lines))
    folded = sum(e.message.count("\n") for e in events)
    nonblank = sum(1 for ln in lines if ln.strip())
    # No real line is silently dropped: every one is an event, folded into an
    # event, or counted as table furniture.
    assert len(events) + parser.meta_lines + folded == nonblank


def test_json_fixture_detects(fixtures_dir):
    path = fixtures_dir / "restic_json.log"
    lines = path.read_text().splitlines()
    assert detect_parser(path, lines[:40]).FORMAT_NAME == "restic"
