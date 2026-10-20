from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser, level_to_severity

# dnf5 (/var/log/dnf5.log, RHEL 10 / Fedora 41+ / CentOS Stream 10) replaced the
# "Mon DD HH:MM:SS Installed: pkg" yum.log shape entirely — it is ISO-8601 with
# an offset, a bracketed pid, and a level:
#   2026-04-26T07:47:38+0000 [48] INFO --- DNF5 launched with arguments: "..." ---
#   2026-04-26T07:47:38+0000 [48] DEBUG Loading system repo rpmdb from root "/"
#   2026-04-26T07:47:41+0000 [48] WARNING Failed to resolve package "foo"
# Nothing in the yum parser matches it, so before this parser a real dnf5.log
# fell to syslog at 17/2718 lines (measured on evidence/os-2026-07-28/dnf5.log).
_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?) "
    r"\[(?P<pid>\d+)\] "
    r"(?P<level>CRITICAL|ERROR|WARNING|INFO|DEBUG|TRACE) "
    r"(?P<message>.*)$"
)
# "--- DNF5 launched with arguments: ... ---" / "--- DNF5 finished ---" banners.
_TRANSACTION_RE = re.compile(r"^--- (?P<event>DNF5 \w+)")


class Dnf5Parser(LogParser):
    FORMAT_NAME = "dnf5"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if path and re.search(r"dnf5(\.\w+)?\.log", path.name.lower()):
            return True
        matched = sum(1 for ln in sample_lines[:20] if _PATTERN.match(ln))
        nonblank = sum(1 for ln in sample_lines[:20] if ln.strip())
        return nonblank > 0 and matched * 2 >= nonblank

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        extra: dict[str, object] = {"pid": m["pid"], "level": m["level"]}
        banner = _TRANSACTION_RE.match(message)
        if banner:
            extra["transaction"] = banner["event"]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(m["level"]),
            source="dnf5",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )


# dnf 4 (/var/log/dnf.log and dnf.rpm.log) — still the package manager on RHEL
# 10.2, AlmaLinux 10.2 and CentOS Stream 10, not just EL8/EL9: on real GCP VMs
# (2026-10-13) none of the EL10 distros shipped dnf5. Same ISO-8601 shape as
# dnf5 but with no "[pid]", and dnf's own level words:
#   2026-09-08T15:15:33+0000 INFO --- logging initialized ---
#   2026-09-08T15:15:33+0000 DDEBUG timer: config: 11 ms
#   2026-09-08T15:15:41+0000 SUBDEBUG Installed: nginx-2:1.26.3-6.el10_2.7.x86_64
#   2026-09-08T15:15:09+0000 ERROR Error in POSTIN scriptlet in rpm package ...
# Before this parser dnf.log was path-routed to `yum`, which matched 0/1720
# lines on RHEL 10, so the file fell to generic.
_DNF4_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<level>CRITICAL|ERROR|WARNING|INFO|DEBUG|DDEBUG|SUBDEBUG|TRACE) "
    r"(?P<message>.*)$"
)
# The transaction table (" Package  Arch  Version ...", "Installing:", "====")
# is printed under an INFO record with no timestamp of its own.
_DNF4_CONTINUATION = re.compile(r"^(?!\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S|^\s")
# dnf logs a routine GPG key import at CRITICAL (the key-confirmation prompt).
# All 5 CRITICAL records across the 5 EL captures were exactly this.
_GPG_IMPORT_RE = re.compile(r"^Importing GPG key\b")
_DNF_BANNER = re.compile(r"^--- logging initialized ---")
_DNF4_SEVERITY = {"DDEBUG": "DEBUG", "SUBDEBUG": "DEBUG"}


class DnfParser(LogParser):
    FORMAT_NAME = "dnf"
    CONTINUATION = _DNF4_CONTINUATION

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        hits = [m for ln in sample_lines[:20] if (m := _DNF4_PATTERN.match(ln))]
        nonblank = sum(1 for ln in sample_lines[:20] if ln.strip())
        if path and re.fullmatch(r"dnf(\.rpm)?\.log(\.\d+)?", path.name.lower()):
            # dnf.log may open with an untimestamped table fragment after
            # rotation; one dnf-shaped line in the sample is enough by name.
            return bool(hits)
        # "ISO-8601 LEVEL message" alone is a generic shape (Trino, many Java
        # and Go services) — by content, also require something only dnf emits:
        # its private DDEBUG/SUBDEBUG levels or its logging banner.
        dnf_only = any(
            m["level"] in ("DDEBUG", "SUBDEBUG") or _DNF_BANNER.match(m["message"])
            for m in hits
        )
        return dnf_only and nonblank > 0 and len(hits) * 2 >= nonblank

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _DNF4_PATTERN.match(line)
        if not m:
            return None
        try:
            ts = dateparser.parse(m["ts"])
        except (ValueError, TypeError, OverflowError):
            ts = None
        message = m["message"].strip()
        level = _DNF4_SEVERITY.get(m["level"], m["level"])
        extra: dict[str, object] = {"level": m["level"]}
        if level == "CRITICAL" and _GPG_IMPORT_RE.match(message):
            level = "INFO"
        elif level == "CRITICAL" and message.startswith("Error: "):
            # dnf's own record that the command failed — real GCP VMs (EL8/9/10):
            #   CRITICAL Error: Unable to find a match: lc-no-such-package-xyz
            # The run's earlier "No match for argument" is only INFO.
            extra["outcome"] = "failed"
            extra["detail"] = message[len("Error: "):]
        return ParsedEvent(
            timestamp=ts,
            severity=level_to_severity(level),
            source="dnf",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
