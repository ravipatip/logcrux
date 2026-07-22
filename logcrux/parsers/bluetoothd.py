from __future__ import annotations

from logcrux.parsers.base import SyslogKeywordParser

# BlueZ Bluetooth daemon syslog output. Tagged "bluetoothd":
#   Jun 28 10:15:01 host bluetoothd[1234]: Bluetooth daemon 5.66
#   Jun 28 10:15:02 host bluetoothd[1234]: Endpoint registered: sender=:1.42 path=/A2DP
#   Jun 28 10:15:03 host bluetoothd[1234]: Failed to set mode: Blocked through rfkill (0x12)


class BluetoothdParser(SyslogKeywordParser):
    FORMAT_NAME = "bluetoothd"
    SOURCE = "bluetoothd"
    TAG_PATTERN = r"bluetoothd"
    ERROR_KW = ("failed", "error", "cannot", "refused", "rejected", "not available",
                "no such", "unable", "blocked")
    WARN_KW = ("retry", "disconnect", "timeout", "unavailable", "deprecated")
