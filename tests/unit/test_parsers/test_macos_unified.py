"""macOS unified log (`log show`), from a real capture on macOS 26 (2026-10-20,
anonymised). Before this parser the idle 3-minute capture was generic text,
spanned a week (dates inside folded plist lines) and reported a 9,000-error
"burst" built from routine "...failed for eventName" lines."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from logcrux.cli import app
from logcrux.models import Severity
from logcrux.parsers.macos_unified import MacOSUnifiedParser
from logcrux.parsers.registry import detect_parser

FIXTURES = Path(__file__).parent.parent.parent / "fixtures"
STYLES = ["macos_unified_default.log", "macos_unified_compact.log", "macos_unified_syslog.log"]


@pytest.mark.parametrize("name", STYLES)
def test_detects_and_parses_every_style(name):
    lines = (FIXTURES / name).read_text().splitlines()
    assert detect_parser(None, lines[:20]).FORMAT_NAME == "macos-unified"
    p = MacOSUnifiedParser()
    events = list(p.parse_stream(iter(ln + "\n" for ln in lines)))
    assert len(events) > 100
    assert len(events) + p.meta_lines == len([ln for ln in lines if ln.strip()])
    assert all(e.timestamp is not None for e in events)


def test_headerless_tail_still_detects():
    lines = (FIXTURES / "macos_unified_default.log").read_text().splitlines()[50:70]
    assert detect_parser(None, lines).FORMAT_NAME == "macos-unified"


def test_levels_are_macos_own_not_keywords():
    p = MacOSUnifiedParser()
    err = p.parse_line("2026-10-20 06:36:28.938000+1100 0x1e2424   Error       0x0      "
                       "            1      0    launchd: invalid client reply port -1", 1)
    fault = p.parse_line("2026-10-20 06:10:16.835437+1100 0x195fd0   Fault       0x313470 "
                         "            44016  14   PerfPowerServices: (CoreAnalytics) Error: x", 2)
    dflt = p.parse_line("2026-10-20 06:36:27.888749+1100 0x1   Default     0x0          "
                        "        0      0    kernel: SendEvent failed for eventName", 3)
    assert err.severity == Severity.INFO and fault.severity == Severity.WARNING
    assert dflt.severity == Severity.INFO and dflt.source == "kernel"


@pytest.mark.parametrize("name", STYLES)
def test_idle_mac_is_clean(name):
    r = CliRunner().invoke(app, [str(FIXTURES / name), "--no-baseline", "--json"])
    data = json.loads(r.output)
    assert data["level"] == "CLEAN", data["findings"]
    assert data["time_range"]["duration_seconds"] < 600
