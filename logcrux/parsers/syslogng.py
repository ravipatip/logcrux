from __future__ import annotations

from logcrux.parsers.base import SyslogKeywordParser

# syslog-ng collector daemon's own diagnostic messages (not the logs it relays).
# Tagged "syslog-ng":
#   Jun 28 10:15:01 host syslog-ng[1234]: syslog-ng starting up; version='4.5.0'
#   Jun 28 10:15:02 host syslog-ng[1234]: Configuration reload finished
#   Jun 28 10:15:03 host syslog-ng[1234]: Syslog connection broken; fd='12', server='10.0.0.9:514'
#   Jun 28 10:15:04 host syslog-ng[1234]: Error opening file for reading; filename='/var/log/x'


class SyslogNgParser(SyslogKeywordParser):
    FORMAT_NAME = "syslogng"
    SOURCE = "syslog-ng"
    TAG_PATTERN = r"syslog-ng"
    ERROR_KW = ("error", "cannot", "failed", "broken", "refused", "no such",
                "unable", "denied", "dropping")
    WARN_KW = ("warning", "reopen", "suspending", "retry", "overflow",
               "reload", "disconnect", "timed out")
