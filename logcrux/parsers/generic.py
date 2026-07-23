from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

_TS_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[Z+]\S*)?)"
)
# Severity keywords are matched as *whole words* (with common inflections), not
# as substrings. Substring matching mistook identifiers and method names like
# ``ReturningError``/``NSError``/``errorDomain`` for real ERROR lines, flooding
# free-text logs (e.g. macOS install.log) with thousands of false errors. Order
# is most-severe first so the strongest indicator on a line wins.
_SEVERITY_PATTERNS: list[tuple[re.Pattern[str], Severity]] = [
    (re.compile(r"\b(critical|crit|emerg(?:ency)?|alert|fatal|panic)\b", re.I), Severity.CRITICAL),
    (re.compile(r"\b(error|errors|err|fail(?:ed|ure|ures|s)?)\b", re.I), Severity.ERROR),
    (re.compile(r"\b(warn(?:ing)?)\b", re.I), Severity.WARNING),
    (re.compile(r"\b(info|notice)\b", re.I), Severity.INFO),
    (re.compile(r"\b(debug|trace)\b", re.I), Severity.DEBUG),
]

# A keyword is a *severity level* only when used as a status label, not as a
# count, an error code, or an adjective/noun in prose. Free-text logs (macOS
# install.log) are full of benign mentions — "Critical updates: []", "0 Critical
# product(s)", "returned 0 error Success!", "(error 30)" — that whole-word
# matching alone reads as real incidents, flooding analysis with false errors.
# These guards reject the common non-level usages while leaving genuine level
# tokens ("ERROR ...", "connection failed:", "a warning about ...") untouched.

# "0 error", "4 ... Critical", "2 failures" — a keyword right after a number is a
# count of things, not this line's level.
_COUNT_PREFIX = re.compile(r"\d+\s*$")
# "error 30", "err 0xb" — a keyword immediately followed by a number is an error
# *code* reference, common in benign status lines.
_CODE_SUFFIX = re.compile(r"^\s*[0-9]")
# CRITICAL is the tier that escalates a whole incident to CRITICAL, so it demands
# a strong marker: an upper-case level token (CRITICAL/FATAL/PANIC) or a
# delimited field. A capitalised adjective ("Critical updates", "Critical path")
# in prose must not raise a CRITICAL incident.
_CRITICAL_DELIMITED = re.compile(r"[\[\]<>():=]")


def _is_level_usage(text: str, match: re.Match[str], severity: Severity) -> bool:
    before = text[: match.start()]
    after = text[match.end() :]
    token = match.group(0)
    # A number right before the keyword usually means a *count* ("0 error",
    # "2 failures") — but not when the keyword is an ALL-CAPS level label. Many
    # formats put a numeric field (PID, worker id) immediately before the level
    # token: "<ts> 25746 WARNING nova.compute ...", "[12345] INFO ...". There the
    # number is not a count of the keyword, and dropping the level made a
    # warning/critical flood in any such format (OpenStack/nova and other
    # "<pid> LEVEL" shapes fall to the generic parser) read as UNKNOWN and go
    # undetected. Prose counts are lower/mixed case ("0 warnings"), so requiring
    # all-caps keeps those rejected.
    if _COUNT_PREFIX.search(before) and not token.isupper():
        return False
    if severity is Severity.ERROR and _CODE_SUFFIX.match(after):
        return False
    if severity is Severity.CRITICAL:
        # Accept only an all-caps token (CRITICAL, FATAL) or one sitting in a
        # delimited level field; a mixed-case adjective in prose is not a level.
        delimited = (
            before.endswith(("[", "<", "("))
            or after.startswith(("]", ">", ")", ":"))
            or "=" in before[-12:]
        )
        if not (token.isupper() or delimited):
            return False
    return True


def _extract_severity(text: str) -> Severity:
    for pattern, sev in _SEVERITY_PATTERNS:
        for match in pattern.finditer(text):
            if _is_level_usage(text, match, sev):
                return sev
    return Severity.UNKNOWN


class GenericParser(LogParser):
    FORMAT_NAME = "generic"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        return True

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line.strip():
            return None
        ts = None
        m = _TS_PATTERN.search(line)
        if m:
            try:
                ts = dateparser.parse(m["ts"])
            except Exception:
                pass
        return ParsedEvent(
            timestamp=ts,
            severity=_extract_severity(line),
            source="generic",
            message=line,
            raw=line,
            line_number=line_number,
        )
