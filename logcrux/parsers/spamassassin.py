from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, syslog_tag_dominant

# SpamAssassin spam scanner (spamd) syslog output. Tagged "spamd":
#   Jun 28 10:15:01 host spamd[1234]: spamd: connection from localhost
#   Jun 28 10:15:02 host spamd[1234]: spamd: result: Y 12 - BAYES_99,HTML_MESSAGE
#   Jun 28 10:15:03 host spamd[1234]: spamd: result: . 1 - ALL_TRUSTED
#   Jun 28 10:15:04 host spamd[1234]: spamd: error: failed to load Bayes
# The "spamd[pid]: spamd:" tag with "result: Y/." verdicts is the signature.
_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) spamd\[(?P<pid>\d+)\]: (?P<message>.*)"
)
_CURRENT_YEAR = datetime.now().year


class SpamAssassinParser(LogParser):
    FORMAT_NAME = "spamassassin"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return syslog_tag_dominant(sample_lines, _PATTERN, path=path)

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(f"{m['month']} {m['day']} {_CURRENT_YEAR} {m['time']}")
        except Exception:
            ts = None
        message = m["message"].strip()
        low = message.lower()
        severity = Severity.INFO
        extra: dict[str, object] = {"pid": m["pid"]}
        result_m = re.search(r"result:\s+(\S+)\s+(-?\d+)", message)
        if result_m:
            verdict = result_m.group(1)
            extra["verdict"] = "spam" if verdict == "Y" else "ham"
            extra["score"] = result_m.group(2)
            if verdict == "Y":
                severity = Severity.WARNING  # message classified as spam
        if "error" in low or "failed" in low or "cannot" in low:
            severity = Severity.ERROR
        return ParsedEvent(
            timestamp=ts,
            severity=severity,
            source="spamassassin",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
