from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser

# Linux audit daemon (/var/log/audit/audit.log). Every record begins with a
# type and an audit() timestamp carrying epoch seconds + a serial:
#   type=SYSCALL msg=audit(1716113701.123:456): arch=c000003e syscall=59 success=yes ...
#   type=USER_AUTH msg=audit(1716113702.001:457): pid=1234 ... res=failed acct="root" ...
#   type=AVC msg=audit(1716113703.500:458): avc:  denied  { read } for  pid=999 comm="nginx"
# Newer enriched logs may also prefix a node= field; tolerate it.
_PATTERN = re.compile(
    r"(?:node=\S+ )?"
    r"type=(?P<type>\S+) "
    r"msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s*"
    r"(?P<message>.*)"
)

_RES_RE = re.compile(r"\bres=(?:success|failed|\d)|\bsuccess=(?:yes|no)")
_ACCT_RE = re.compile(r'\bacct="?([^"\s]+)"?')
_ADDR_RE = re.compile(r"\baddr=(\d{1,3}(?:\.\d{1,3}){3})")

# Record types that are inherently security-relevant.
_AUTH_FAIL_TYPES = frozenset(
    ["USER_AUTH", "USER_LOGIN", "ANOM_LOGIN_FAILURES", "ANOM_ABEND",
     "USER_ACCT", "CRED_ACQ", "ANOM_PROMISCUOUS"]
)
_DENY_TYPES = frozenset(["AVC", "SELINUX_ERR", "USER_AVC", "MAC_POLICY_LOAD"])
_ANOMALY_TYPES = frozenset(
    ["ANOM_LOGIN_FAILURES", "ANOM_ABEND", "ANOM_PROMISCUOUS",
     "ANOM_ACCESS_FS", "INTEGRITY_DATA", "AVC_PATH"]
)


def _audit_severity(rec_type: str, message: str) -> Severity:
    low = message.lower()
    failed = "res=failed" in low or "success=no" in low
    if rec_type in _ANOMALY_TYPES:
        return Severity.ERROR
    if rec_type in _DENY_TYPES and "denied" in low:
        return Severity.WARNING
    if rec_type in _AUTH_FAIL_TYPES and failed:
        return Severity.WARNING
    if failed:
        return Severity.WARNING
    return Severity.INFO


class AuditdParser(LogParser):
    FORMAT_NAME = "auditd"

    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        # Match the real auditd log precisely: the file is /var/log/audit/audit.log
        # (rotated audit.log.1, ...), i.e. a name that *starts* with "audit" or
        # lives in an "audit" directory. A loose "audit" substring used to hijack
        # unrelated structured logs whose name merely contains it — kubeaudit
        # (k8s API audit), vaultaudit — sending them to the generic fallback and
        # silently dropping their structured parse.
        if path is not None:
            name = path.name.lower()
            if name.startswith("audit") or path.parent.name.lower() == "audit":
                return True
        return any("msg=audit(" in line for line in sample_lines[:10])

    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        if not line:
            return None
        m = _PATTERN.match(line)
        if not m:
            return None
        try:
            ts = datetime.fromtimestamp(float(m["epoch"]), tz=timezone.utc)
        except Exception:
            ts = None
        rec_type = m["type"]
        message = m["message"].strip()
        extra: dict[str, object] = {"record_type": rec_type, "serial": m["serial"]}
        acct = _ACCT_RE.search(message)
        if acct:
            extra["acct"] = acct.group(1)
        addr = _ADDR_RE.search(message)
        if addr:
            extra["addr"] = addr.group(1)
        if "res=failed" in message or "success=no" in message:
            extra["result"] = "failed"
        return ParsedEvent(
            timestamp=ts,
            severity=_audit_severity(rec_type, message),
            source="auditd",
            message=f"{rec_type}: {message}",
            raw=line,
            line_number=line_number,
            extra=extra,
        )
