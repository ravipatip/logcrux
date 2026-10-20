from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# restic backup output, as captured from a real restic/restic container driving
# an S3 (minio) backend in the project's test lab.
#
# The defining property of this format: **plain restic output carries no
# timestamps at all.** It is a CLI tool whose output reaches a log only via cron
# or a systemd unit, so every line below yields ``timestamp=None`` except the
# rows of a `restic snapshots` table, which carry their own. Anything that
# time-orders or windows events (``--last``) has to tolerate that.
#
#   no parent snapshot found, will read all files
#   error: failed to save /data/blob.bin: read /data/blob.bin: input/output error
#   Files:           3 new,     0 changed,     0 unmodified
#   processed 3 files, 478.536 KiB in 0:00
#   snapshot b252f12f saved
#   Warning: at least one source file could not be read
#   Fatal: wrong password or no key found
#
# With ``--json`` the same run emits one object per line, keyed by
# ``message_type`` (status / summary / error / verbose_status).

_SNAPSHOT_SAVED = re.compile(r"^snapshot (?P<id>[0-9a-f]{8,}) saved$")
_REPO_CREATED = re.compile(r"^created restic repository (?P<id>[0-9a-f]{8,}) at (?P<repo>.+)$")
_PARENT = re.compile(r"^using parent snapshot (?P<id>[0-9a-f]{8,})$")
_COUNTS = re.compile(
    r"^(?P<kind>Files|Dirs):\s+(?P<new>\d+) new,\s+(?P<changed>\d+) changed,"
    r"\s+(?P<unmodified>\d+) unmodified$"
)
_PROCESSED = re.compile(
    r"^processed (?P<files>\d+) files?, (?P<size>[\d.]+ \w+) in (?P<duration>[\d:]+)$"
)
_ADDED = re.compile(r"^Added to the repository: (?P<size>[\d.]+ \w+)\s*\((?P<stored>[^)]+)\)$")
# A backend that keeps failing produces nothing but these, forever — restic
# never gives up on its own. A backup that is "running" but has emitted only
# retries for an hour is the single most important incident this format has, so
# the retry delay is extracted for the detectors to threshold on.
_RETRY = re.compile(
    r"^(?P<op>\w+)\((?P<target>[^)]*)\) returned error, retrying after "
    r"(?P<delay>[\dsmhµ.]+): (?P<reason>.+)$"
)
# The complement to the retry storm: restic announcing it got through. Without
# this, a log that recovered looks identical to one still retrying.
_RETRY_OK = re.compile(
    r"^(?P<op>\w+)\((?P<target>[^)]*)\) operation successful after "
    r"(?P<retries>\d+) retries?$"
)
_SIGNAL = re.compile(r"^signal (?P<signal>\w+) received, cleaning up\s*$")
_TEMP_CACHE = re.compile(r"^using temporary cache in (?P<path>\S+)$")
# `restic check` phase announcements and its verdict.
_CHECK_PHASE = re.compile(
    r"^(create exclusive lock for repository|load indexes|check all packs"
    r"|check snapshots, trees and blobs|no errors were found)$"
)
_PROGRESS = re.compile(r"^\[[\d:]+\]\s+[\d.]+%")
_SKIPPED = re.compile(r"^(?P<path>\S.*) does not exist, skipping$")
_SAVE_ERROR = re.compile(r"^error: (?P<detail>.+)$")
_FATAL = re.compile(r"^Fatal: (?P<detail>.+)$")
_WARNING = re.compile(r"^Warning: (?P<detail>.+)$")
_PARTIAL = re.compile(r"at least one source file could not be read")
# `restic snapshots` table row: id, date, host, [tags], paths, size.
_SNAPSHOT_ROW = re.compile(
    r"^(?P<id>[0-9a-f]{8})\s+(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)
# Table furniture and trailers — real output, but not events. Counted as
# meta_lines so they neither inflate "unparsed" nor drag coverage under the
# generic-parser fallback threshold.
_NOISE = re.compile(
    r"^(-{5,}|ID\s+Time\s+Host.*|Timestamps shown in \w+|\d+ snapshots?)$"
)
_JSON_MESSAGE_TYPES = frozenset(
    ["status", "summary", "error", "verbose_status", "exit_error"]
)
_JSON_SEVERITY = {
    "error": Severity.ERROR,
    "exit_error": Severity.ERROR,
}


class ResticParser(LogParser):
    FORMAT_NAME = "restic"
    # A Fatal is followed by two unindented lines naming the repository it
    # could not reach; folding them keeps the location attached to the failure
    # instead of leaving it as an orphaned URL.
    CONTINUATION = re.compile(
        r"^(Is there a repository at the following location\?"
        r"|(?:s3|b2|sftp|rest|azure|gs|swift|rclone):\S+)$"
    )
    # restic emits long runs of progress/table lines around a handful of real
    # events, so the default 0.6 event-per-line floor would push a healthy
    # backup log to the generic parser.
    MIN_COVERAGE = 0.3

    @classmethod
    def _is_restic_json(cls, line: str) -> dict[str, Any] | None:
        if not line.startswith("{") or '"message_type"' not in line:
            return None
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            return None
        if not isinstance(obj, dict):
            return None
        return obj if obj.get("message_type") in _JSON_MESSAGE_TYPES else None

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and re.search(r"restic", path.name.lower()):
            return True
        # Content gate: require a marker only restic produces, so a cron log
        # that merely mentions backups can't divert here.
        markers = (
            _SNAPSHOT_SAVED, _REPO_CREATED, _PARENT, _PROCESSED, _ADDED, _RETRY,
        )
        for ln in sample_lines[:40]:
            if cls._is_restic_json(ln):
                return True
            if any(rx.match(ln) for rx in markers):
                return True
        return False

    def _event(
        self,
        severity: Severity,
        message: str,
        line: str,
        line_number: int,
        extra: dict[str, object],
        timestamp: object = None,
    ) -> ParsedEvent:
        return ParsedEvent(
            timestamp=timestamp,  # type: ignore[arg-type]
            severity=severity,
            source="restic",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )

    def _parse_json(self, obj: dict[str, Any], line: str, line_number: int) -> ParsedEvent:
        kind = obj["message_type"]
        extra: dict[str, object] = {"message_type": kind}
        if kind == "summary":
            for key in (
                "files_new", "files_changed", "files_unmodified",
                "total_files_processed", "total_bytes_processed", "snapshot_id",
            ):
                if key in obj:
                    extra[key] = obj[key]
            message = (
                f"summary: {obj.get('total_files_processed', '?')} files processed, "
                f"{obj.get('files_new', '?')} new, "
                f"{obj.get('data_added', '?')} bytes added"
            )
        elif kind in ("error", "exit_error"):
            detail = obj.get("error", {})
            if isinstance(detail, dict):
                detail = detail.get("message", "")
            message = f"{kind}: {detail or obj.get('message', '')}".strip()
            if obj.get("during"):
                extra["during"] = obj["during"]
            if obj.get("item"):
                extra["item"] = obj["item"]
        else:
            message = f"{kind}: {obj.get('action', obj.get('message', ''))}".strip(": ")
        ts = None
        # Only the summary carries wall-clock time; status frames do not.
        for key in ("backup_end", "backup_start", "time"):
            if obj.get(key):
                try:
                    ts = dateparser.parse(str(obj[key]))
                except (ValueError, TypeError, OverflowError):
                    ts = None
                break
        return self._event(
            _JSON_SEVERITY.get(kind, Severity.INFO), message, line, line_number, extra, ts
        )

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line.strip():
            return None
        obj = self._is_restic_json(line)
        if obj is not None:
            return self._parse_json(obj, line, line_number)

        if _NOISE.match(line):
            self.meta_lines += 1
            return None

        m = _FATAL.match(line)
        if m:
            # Fatal aborts the run: the backup did not happen at all, which is a
            # strictly worse state than a partial one and is graded accordingly.
            return self._event(
                Severity.CRITICAL, line, line, line_number,
                {"outcome": "aborted", "detail": m["detail"]},
            )

        m = _RETRY.match(line)
        if m:
            return self._event(
                Severity.WARNING, line, line, line_number,
                {
                    "operation": m["op"],
                    "retry_after": m["delay"],
                    "reason": m["reason"],
                    "backend_retry": True,
                },
            )

        m = _RETRY_OK.match(line)
        if m:
            return self._event(
                Severity.INFO, line, line, line_number,
                {
                    "operation": m["op"],
                    "recovered_after_retries": int(m["retries"]),
                    "backend_retry": True,
                },
            )

        m = _SIGNAL.match(line)
        if m:
            # An interrupted run leaves no snapshot; it is not an error restic
            # chose, but it is still a backup that did not complete.
            return self._event(
                Severity.WARNING, line, line, line_number,
                {"signal": m["signal"], "outcome": "interrupted"},
            )

        m = _TEMP_CACHE.match(line)
        if m:
            return self._event(
                Severity.INFO, line, line, line_number, {"cache_path": m["path"]}
            )

        if _CHECK_PHASE.match(line):
            return self._event(
                Severity.INFO, line, line, line_number,
                {"phase": line, "verified": line == "no errors were found"},
            )

        if _PROGRESS.match(line):
            self.meta_lines += 1
            return None

        m = _SAVE_ERROR.match(line)
        if m:
            return self._event(
                Severity.ERROR, line, line, line_number, {"detail": m["detail"]}
            )

        m = _WARNING.match(line)
        if m:
            extra: dict[str, object] = {"detail": m["detail"]}
            # restic still saves a snapshot, but it is missing files — a
            # partial backup, which an operator must hear about (real capture,
            # 12 distros: the run ends "snapshot ... saved" + this warning).
            if _PARTIAL.match(m["detail"]):
                extra["outcome"] = "partial"
            return self._event(Severity.WARNING, line, line, line_number, extra)

        m = _SKIPPED.match(line)
        if m:
            return self._event(
                Severity.WARNING, line, line, line_number,
                {"skipped_path": m["path"]},
            )

        m = _SNAPSHOT_SAVED.match(line)
        if m:
            return self._event(
                Severity.INFO, line, line, line_number,
                {"snapshot_id": m["id"], "outcome": "saved"},
            )

        m = _REPO_CREATED.match(line)
        if m:
            return self._event(
                Severity.INFO, line, line, line_number,
                {"repository_id": m["id"], "repository": m["repo"]},
            )

        m = _PARENT.match(line)
        if m:
            return self._event(
                Severity.INFO, line, line, line_number, {"parent_snapshot": m["id"]}
            )

        m = _COUNTS.match(line)
        if m:
            kind = m["kind"].lower()
            return self._event(
                Severity.INFO, " ".join(line.split()), line, line_number,
                {
                    f"{kind}_new": int(m["new"]),
                    f"{kind}_changed": int(m["changed"]),
                    f"{kind}_unmodified": int(m["unmodified"]),
                },
            )

        m = _PROCESSED.match(line)
        if m:
            return self._event(
                Severity.INFO, line, line, line_number,
                {
                    "files_processed": int(m["files"]),
                    "size": m["size"],
                    "duration": m["duration"],
                },
            )

        m = _ADDED.match(line)
        if m:
            return self._event(
                Severity.INFO, line, line, line_number,
                {"added": m["size"], "stored": m["stored"]},
            )

        m = _SNAPSHOT_ROW.match(line)
        if m:
            try:
                ts = dateparser.parse(m["ts"])
            except (ValueError, TypeError, OverflowError):
                ts = None
            return self._event(
                Severity.INFO, " ".join(line.split()), line, line_number,
                {"snapshot_id": m["id"], "host": m["host"]}, ts,
            )

        if line.startswith("no parent snapshot found"):
            return self._event(
                Severity.INFO, line, line, line_number, {"parent_snapshot": None}
            )
        return None
