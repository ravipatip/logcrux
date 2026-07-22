from __future__ import annotations

import re
from pathlib import Path

from dateutil import parser as dateparser

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser, level_to_severity

# PingFederate (Ping Identity SSO / federation server). Two log shapes ship by
# default from <pf_install>/pingfederate/log:
#
# 1. server.log / admin-api.log / provisioner.log — Log4j2 with a PingFederate-
#    specific "tid:" tracking-ID token wedged between the timestamp and level:
#      2025-09-02 11:02:32,869 tid:Z8I1vdotGu084PB7b2HrQ0A1kKU INFO
#          [org.sourceid.saml20.service.impl.AuthnRequestProcessorImpl] Processing...
#    The "tid:" token is unique to PingFederate and makes detection unambiguous
#    against the generic log4j / keycloak / activemq shapes.
#
# 2. admin.log / audit.log — the pipe-delimited security & administrator audit
#    trail (the operationally important security log):
#      2024-11-28 05:58:55,832 | Administrator | UserAdmin,Admin | 81.2.69.142 |
#          A-rBnN... | LICENSE | ROTATE | - Login was successful
#    Field 2 is a username/subject (never a log level — that is what separates it
#    from the ActiveMQ "ts | LEVEL | ..." pipe layout).
_SERVER_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) "
    r"tid:(?P<tid>\S+) "
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"\[(?P<logger>[^\]]*)\]\s*(?P<message>.*)$"
)

# Pipe-delimited audit/admin line: a Log4j timestamp then " | " fields.
_AUDIT_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}:\d{2},\d{3}) \| (?P<rest>.*)$"
)

_LEVEL_WORDS = frozenset({"TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL"})

# Audit-trail outcomes that are security-relevant even though the audit log
# carries no severity column: a failed SSO/OAuth/admin action is a WARNING.
_AUDIT_FAILURE_RE = re.compile(
    r"\b(?:fail(?:ed|ure)?|denied|invalid|error|reject(?:ed)?|unauthorized|"
    r"forbidden|lockout|locked)\b",
    re.IGNORECASE,
)


def _looks_like_audit(rest: str) -> bool:
    """A PingFederate pipe-audit line: >=5 pipe fields and the second field is a
    subject/component, not a log level (which is how ActiveMQ's pipe layout
    reads). Guards against poaching the ``ts | LEVEL | msg | logger | thread``
    broker log."""
    fields = [f.strip() for f in rest.split("|")]
    if len(fields) < 5:
        return False
    return fields[0].upper() not in _LEVEL_WORDS


class PingFederateParser(LogParser):
    FORMAT_NAME = "pingfederate"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        for ln in sample_lines[:20]:
            if _SERVER_RE.match(ln):
                return True
            m = _AUDIT_RE.match(ln)
            if m and _looks_like_audit(m["rest"]):
                return True
        return False

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        m = _SERVER_RE.match(line)
        if m:
            try:
                ts = dateparser.parse(m["ts"].replace(",", "."))
            except (ValueError, TypeError, OverflowError):
                ts = None
            return ParsedEvent(
                timestamp=ts,
                severity=level_to_severity(m["level"]),
                source="pingfederate",
                message=m["message"].strip(),
                raw=line,
                line_number=line_number,
                extra={
                    "level": m["level"].lower(),
                    "logger": m["logger"],
                    "tid": m["tid"],
                },
            )

        m = _AUDIT_RE.match(line)
        if m and _looks_like_audit(m["rest"]):
            try:
                ts = dateparser.parse(m["ts"].replace(",", "."))
            except (ValueError, TypeError, OverflowError):
                ts = None
            fields = [f.strip() for f in m["rest"].split("|")]
            # The message is the trailing field; PingFederate prefixes it with
            # "- " in the admin log. Keep the whole pipe payload as the message
            # so the audit trail is legible, but score severity off failure verbs.
            message = m["rest"].strip()
            severity = (
                Severity.WARNING if _AUDIT_FAILURE_RE.search(message) else Severity.INFO
            )
            return ParsedEvent(
                timestamp=ts,
                severity=severity,
                source="pingfederate-audit",
                message=message,
                raw=line,
                line_number=line_number,
                extra={"subject": fields[0], "fields": fields},
            )
        return None
