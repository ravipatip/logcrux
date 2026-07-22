from __future__ import annotations

from typing import Any

from logcrux.models import IncidentSummary
from logcrux.state.db import Database


def insert_run(
    db: Database,
    summary: IncidentSummary,
    parser_format: str = "unknown",
    skipped_count: int = 0,
) -> None:
    with db.connection() as conn:
        conn.execute(
            """INSERT INTO analysis_runs
               (id, log_path, ran_at, parser_format, parsed_count, skipped_count,
                signal_count, elapsed_seconds, incident_level, category, confidence, summary_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                summary.analysis_id,
                summary.log_path,
                summary.analyzed_at.isoformat(),
                parser_format,
                summary.parsed_count,
                skipped_count,
                len(summary.findings),
                summary.elapsed_seconds,
                summary.level,
                summary.category.value,
                summary.confidence,
                summary.model_dump_json(),
            ),
        )


def get_recent_runs(db: Database, log_path: str, limit: int = 10) -> list[dict[str, Any]]:
    with db.connection() as conn:
        rows = conn.execute(
            """SELECT id, log_path, ran_at, incident_level, category, confidence
               FROM analysis_runs WHERE log_path = ?
               ORDER BY ran_at DESC LIMIT ?""",
            (log_path, limit),
        ).fetchall()
    return [dict(r) for r in rows]
