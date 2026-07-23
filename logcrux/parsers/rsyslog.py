from __future__ import annotations

from logcrux.parsers.base import SyslogKeywordParser

# rsyslog collector daemon's own diagnostic messages (not the logs it relays).
# Tagged "rsyslogd" (usually without a pid):
#   Jun 28 10:15:01 host rsyslogd: [origin software="rsyslogd" x-pid="1234"] start
#   Jun 28 10:15:02 host rsyslogd: rsyslogd's groupid changed to 110
#   Jun 28 10:15:03 host rsyslogd: action 'action-0-builtin:omfwd' suspended, retry 0
#   Jun 28 10:15:04 host rsyslogd: cannot connect to 10.0.0.9:514: Connection refused
# Unlike systemd, rsyslogd emits only a handful of its own lines, so its tag
# never dominates a mixed /var/log/syslog (guarded by syslog_tag_dominant).


class RsyslogParser(SyslogKeywordParser):
    FORMAT_NAME = "rsyslog"
    SOURCE = "rsyslog"
    TAG_PATTERN = r"rsyslogd"
    ERROR_KW = ("cannot", "error", "failed", "refused", "denied", "no such",
                "unable", "broken")
    WARN_KW = ("suspended", "retry", "reopen", "discarding", "queue full",
               "warning", "could not", "dropped")
