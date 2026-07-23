from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from logcrux.state.db import Database


@dataclass
class BaselineRecord:
    log_path: str
    parser_format: str
    avg_events_per_hour: float
    avg_errors_per_hour: float
    p95_burst_size: float
    sample_count: int


def get_baseline(db: Database, log_path: str) -> BaselineRecord | None:
    with db.connection() as conn:
        row = conn.execute(
            "SELECT * FROM baselines WHERE log_path = ?", (log_path,)
        ).fetchone()
    if row is None:
        return None
    return BaselineRecord(
        log_path=row["log_path"],
        parser_format=row["parser_format"],
        avg_events_per_hour=row["avg_events_per_hour"],
        avg_errors_per_hour=row["avg_errors_per_hour"],
        p95_burst_size=row["p95_burst_size"],
        sample_count=row["sample_count"],
    )


def upsert_baseline(
    db: Database,
    log_path: str,
    parser_format: str,
    avg_events_per_hour: float,
    avg_errors_per_hour: float,
    p95_burst_size: float,
    alpha: float = 0.2,
) -> None:
    existing = get_baseline(db, log_path)
    now = datetime.now(UTC).isoformat()

    if existing is None:
        with db.connection() as conn:
            conn.execute(
                """INSERT INTO baselines
                   (log_path, parser_format, avg_events_per_hour,
                    avg_errors_per_hour, p95_burst_size, sample_count, last_updated)
                   VALUES (?, ?, ?, ?, ?, 1, ?)""",
                (log_path, parser_format, avg_events_per_hour,
                 avg_errors_per_hour, p95_burst_size, now),
            )
    else:
        new_events = alpha * avg_events_per_hour + (1 - alpha) * existing.avg_events_per_hour
        new_errors = alpha * avg_errors_per_hour + (1 - alpha) * existing.avg_errors_per_hour
        new_burst = alpha * p95_burst_size + (1 - alpha) * existing.p95_burst_size
        with db.connection() as conn:
            conn.execute(
                """UPDATE baselines SET
                   avg_events_per_hour = ?, avg_errors_per_hour = ?,
                   p95_burst_size = ?, sample_count = sample_count + 1,
                   last_updated = ?
                   WHERE log_path = ?""",
                (new_events, new_errors, new_burst, now, log_path),
            )
