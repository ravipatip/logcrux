from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.kernel import KernelParser

_OOM = "May 19 10:15:10 web01 kernel: [12355.440000] Out of memory: Killed process 4242 (java) total-vm:8388608kB"
_FS_ERR = "May 19 10:15:07 web01 kernel: [12352.330000] EXT4-fs error (device sda1): ext4_find_entry"
_INFO = "May 19 10:15:00 web01 kernel: [12345.678901] EXT4-fs (sda1): mounted filesystem with ordered data mode"
_DMESG = "[  300.770000] Out of memory: Killed process 9876 (mysqld) total-vm:4194304kB"


@pytest.fixture
def parser():
    return KernelParser()


def test_oom_is_critical(parser):
    event = parser.parse_line(_OOM, 1)
    assert event is not None
    assert event.severity == Severity.CRITICAL
    assert event.source == "kernel"
    assert event.extra["uptime"] == 12355.44


def test_fs_error_is_critical(parser):
    event = parser.parse_line(_FS_ERR, 1)
    assert event is not None
    assert event.severity == Severity.CRITICAL


def test_mount_is_info(parser):
    event = parser.parse_line(_INFO, 1)
    assert event is not None
    assert event.severity == Severity.INFO


def test_xfs_mount_is_not_critical(parser):
    # Regression: a bare "xfs" keyword used to mark every XFS line (including
    # normal mounts) as CRITICAL.
    line = "May 19 10:15:00 web01 kernel: [12345.0] XFS (sda1): Mounting V5 Filesystem"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity != Severity.CRITICAL


@pytest.mark.parametrize("line", [
    "May 19 10:15:00 web01 kernel: [12345.0] XFS (sda1): metadata I/O error",
    "May 19 10:15:00 web01 kernel: [12345.0] XFS (sda1): Corruption detected",
    "May 19 10:15:00 web01 kernel: [12345.0] Kernel panic - not syncing",
])
def test_real_kernel_faults_are_critical(parser, line):
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.CRITICAL


def test_raw_dmesg_has_no_timestamp(parser):
    event = parser.parse_line(_DMESG, 1)
    assert event is not None
    assert event.timestamp is None
    assert event.severity == Severity.CRITICAL
    assert event.extra["uptime"] == 300.77


def test_can_parse_by_path():
    assert KernelParser.can_parse(Path("/var/log/kern.log"), [])
    assert KernelParser.can_parse(None, [_DMESG])


def test_messages_path_defers_to_syslog():
    # Aggregate /var/log/messages must not be claimed by the kernel parser.
    assert not KernelParser.can_parse(Path("/var/log/messages"), [_OOM])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


@pytest.mark.parametrize("line,expected_severity", [
    (
        "[Tue Jun 16 03:41:00 2026] Out of memory: Killed process 4242 (java) total-vm:8GB",
        Severity.CRITICAL,
    ),
    (
        "[Tue Jun 16 03:41:01 2026] kernel panic - not syncing: VFS: Unable to mount root",
        Severity.CRITICAL,
    ),
    (
        "[Tue Jun 16 03:41:02 2026] EXT4-fs error (device sda1): ext4_find_entry:1455",
        Severity.CRITICAL,
    ),
    (
        "[Tue Jun 16 03:41:03 2026] usb 1-1: new high-speed USB device number 5 using xhci_hcd",
        Severity.INFO,
    ),
])
def test_dmesg_T_human_timestamp(parser, line, expected_severity):
    event = parser.parse_line(line, 1)
    assert event is not None, f"dmesg -T line returned None: {line!r}"
    assert event.severity == expected_severity
    assert event.timestamp is not None


def test_dmesg_T_no_uptime_in_extra(parser):
    line = "[Tue Jun 16 03:41:00 2026] EXT4-fs (sda1): mounted"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert "uptime" not in event.extra


def test_dmesg_T_can_parse_by_content():
    line = "[Tue Jun 16 03:41:00 2026] Out of memory: Killed process 99"
    assert KernelParser.can_parse(None, [line])
