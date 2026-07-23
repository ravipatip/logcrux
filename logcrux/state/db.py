from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from logcrux.exceptions import StateError

_SCHEMA_VERSION = 1

_DDL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS baselines (
    id                   INTEGER PRIMARY KEY,
    log_path             TEXT NOT NULL UNIQUE,
    parser_format        TEXT NOT NULL,
    avg_events_per_hour  REAL,
    avg_errors_per_hour  REAL,
    p95_burst_size       REAL,
    sample_count         INTEGER NOT NULL DEFAULT 0,
    last_updated         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analysis_runs (
    id               TEXT PRIMARY KEY,
    log_path         TEXT NOT NULL,
    ran_at           TEXT NOT NULL,
    parser_format    TEXT NOT NULL,
    parsed_count     INTEGER NOT NULL,
    skipped_count    INTEGER NOT NULL DEFAULT 0,
    signal_count     INTEGER NOT NULL,
    elapsed_seconds  REAL NOT NULL,
    incident_level   TEXT,
    category         TEXT,
    confidence       REAL,
    summary_json     TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_log_path_time
    ON analysis_runs(log_path, ran_at DESC);
"""


class Database:
    def __init__(self, db_path: Path) -> None:
        self._path = db_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._migrate()
        except Exception as exc:
            raise StateError(f"Cannot initialize database at {db_path}: {exc}") from exc

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self._path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _migrate(self) -> None:
        with self.connection() as conn:
            conn.executescript(_DDL)
            version_rows = conn.execute("SELECT version FROM schema_version").fetchall()
            if not version_rows:
                conn.execute("INSERT INTO schema_version VALUES (?)", (_SCHEMA_VERSION,))
