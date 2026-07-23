from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# Apache Hadoop daemon logs (HDFS NameNode/DataNode, YARN ResourceManager/
# NodeManager, MapReduce). The default log4j layout is
# "ts LEVEL [thread] logger: message" (colon, not the " - " dash form):
#   2026-06-28 10:15:01,123 INFO  [main] namenode.NameNode: STARTUP_MSG: Starting
#   2026-06-28 10:15:02,456 WARN  org.apache.hadoop.hdfs.StateChange: BLOCK* ...
#   2026-06-28 10:15:03,789 ERROR datanode.DataNode: Exception in receiveBlock
# Detection requires Hadoop vocabulary in the sample so this never poaches a
# generic log4j log; parse_line then accepts any timestamped continuation line.
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+"
    r"(?P<rest>.*)$"
)
# Classic HDFS daemon layout (%d{yyMMdd HHmmss} + thread id), still what the
# widely-mirrored production HDFS corpora ship and what older clusters emit:
#   081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder ...
_CLASSIC_PATTERN = re.compile(
    r"^(?P<date>\d{6}) (?P<time>\d{6}) (?P<thread>\d+) "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+"
    r"(?P<rest>.*)$"
)
_HADOOP_MARKERS = ("org.apache.hadoop", "namenode.", "datanode.",
                   "BlockManager", "FSNamesystem", "ResourceManager",
                   "NodeManager", "STARTUP_MSG", "yarn.", "mapreduce.",
                   "hdfs.", "dfs.", "BLOCK*")
_THREAD_RE = re.compile(r"^\[(?P<thread>[^\]]+)\]\s+(?P<rest>.*)$")


class HadoopParser(LogParser):
    FORMAT_NAME = "hadoop"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        matched = [
            ln for ln in sample_lines[:25]
            if _PATTERN.match(ln) or _CLASSIC_PATTERN.match(ln)
        ]
        if not matched:
            return False
        return any(mk in ln for ln in matched for mk in _HADOOP_MARKERS)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        ts: datetime | None
        if m:
            try:
                ts = dateparser.parse(m["ts"].replace(",", "."))
            except (ValueError, TypeError, OverflowError):
                ts = None
        else:
            m = _CLASSIC_PATTERN.match(line)
            if not m:
                return None
            try:
                ts = datetime.strptime(f"{m['date']} {m['time']}", "%y%m%d %H%M%S")
            except ValueError:
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
            source="hadoop",
            message=message.strip(),
            raw=line,
            line_number=line_number,
            extra=extra,
        )
