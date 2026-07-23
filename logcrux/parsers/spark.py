from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Apache Spark driver/executor logs (log4j default layout, colon logger form):
#   2026-06-28 10:15:01,123 INFO  org.apache.spark.SparkContext: Running Spark 3.5
#   2026-06-28 10:15:02,456 WARN  spark.TaskSetManager: Lost task 3.0 in stage 2
#   2026-06-28 10:15:03,789 ERROR executor.Executor: Exception in task 1.0
# Detection requires Spark vocabulary so it never poaches a generic log4j or a
# Hadoop log; parse_line accepts any timestamped continuation line.
# The second timestamp form is Spark's stock conf/log4j.properties template
# (%d{yy/MM/dd HH:mm:ss}) — what real Spark-on-YARN driver/executor logs use:
#   17/06/09 20:10:40 INFO executor.CoarseGrainedExecutorBackend: Registered ...
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}|\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+"
    r"(?P<rest>.*)$"
)
_SPARK_MARKERS = ("org.apache.spark", "spark.", "SparkContext",
                  "TaskSetManager", "DAGScheduler", "executor.Executor",
                  "BlockManager", "MemoryStore", "Spark Executor", "stage")
_THREAD_RE = re.compile(r"^\[(?P<thread>[^\]]+)\]\s+(?P<rest>.*)$")


class SparkParser(LogParser):
    FORMAT_NAME = "spark"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [ln for ln in sample_lines[:25] if _PATTERN.match(ln)]
        if not matched:
            return False
        hits = sum(1 for ln in matched for mk in _SPARK_MARKERS if mk in ln)
        # Require a Spark package/class marker (not just the generic word
        # "stage") to claim the file.
        return any(
            mk in ln for ln in matched for mk in _SPARK_MARKERS[:9]
        ) and hits > 0


    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        raw_ts = m["ts"]
        try:
            if "/" in raw_ts:
                # yy/MM/dd is ambiguous to dateutil; parse it explicitly.
                ts = datetime.strptime(raw_ts, "%y/%m/%d %H:%M:%S")
            else:
                ts = dateparser.parse(raw_ts.replace(",", "."))
        except (ValueError, TypeError, OverflowError):
            ts = None
        rest = m["rest"]
        extra: dict[str, object] = {"level": m["level"].lower()}
        tm = _THREAD_RE.match(rest)
        if tm:
            extra["thread"] = tm["thread"]
            rest = tm["rest"]
        logger_split = re.match(r"^(?P<logger>[\w.$]+): (?P<message>.*)$", rest)
        if logger_split:
            extra["logger"] = logger_split["logger"]
            message = logger_split["message"]
        else:
            message = rest
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="spark",
            message=message.strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
