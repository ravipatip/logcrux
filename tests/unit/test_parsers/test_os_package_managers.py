"""dnf5 / zypp-history / macOS install.log — the three OS package-manager gaps
found against v0.9.0 on real captures (2026-07-28).

Before these parsers existed a real dnf5.log detected as ``syslog`` and matched
17 of 2718 lines; zypp history and install.log both fell to ``generic``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.dnf5 import Dnf5Parser
from logcrux.parsers.macosinstall import MacOSInstallParser
from logcrux.parsers.registry import detect_parser
from logcrux.parsers.zypp import ZyppHistoryParser


def _lines(fixtures_dir: Path, name: str) -> list[str]:
    return (fixtures_dir / name).read_text().splitlines()


# --------------------------------------------------------------------- dnf5


@pytest.fixture
def dnf5():
    return Dnf5Parser()


def test_dnf5_parses_level_and_offset_timestamp(dnf5):
    event = dnf5.parse_line(
        '2026-04-26T07:47:38+0000 [48] WARNING Failed to resolve package "oldpkg"', 1
    )
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.source == "dnf5"
    assert event.extra["pid"] == "48"
    assert event.timestamp is not None
    assert event.timestamp.utcoffset() is not None  # offset kept, not dropped


def test_dnf5_trace_maps_to_debug(dnf5):
    event = dnf5.parse_line("2026-04-26T07:47:42+0000 [48] TRACE rpm callback", 1)
    assert event is not None and event.severity == Severity.DEBUG


def test_dnf5_marks_transaction_banners(dnf5):
    event = dnf5.parse_line(
        '2026-04-26T07:47:38+0000 [48] INFO --- DNF5 launched with arguments: "x" ---', 1
    )
    assert event is not None and event.extra["transaction"] == "DNF5 launched"


def test_dnf5_rejects_legacy_yum_line(dnf5):
    assert dnf5.parse_line("Jun 20 10:15:01 Installed: nginx-1.24.0-1.el9.x86_64", 1) is None


def test_dnf5_can_parse_by_path():
    assert Dnf5Parser.can_parse(Path("/var/log/dnf5.log"), [])
    assert Dnf5Parser.can_parse(Path("/var/log/dnf5.librepo.log"), [])
    # Legacy dnf.log keeps the yum shape and must not be claimed by path alone.
    assert not Dnf5Parser.can_parse(Path("/var/log/dnf.log"), ["Jun 20 10:15:01 Installed: x"])


def test_dnf5_fixture_is_fully_parsed(fixtures_dir, dnf5):
    lines = _lines(fixtures_dir, "dnf5.log")
    assert detect_parser(fixtures_dir / "dnf5.log", lines).FORMAT_NAME == "dnf5"
    assert all(dnf5.parse_line(ln, i) for i, ln in enumerate(lines))


# --------------------------------------------------------------- zypp history


@pytest.fixture
def zypp():
    return ZyppHistoryParser()


def test_zypp_install_fields(zypp):
    event = zypp.parse_line(
        "2026-07-28 00:15:52|install|zsh|5.9-160000.1.5|aarch64|root@h|repo-oss|abc|", 1
    )
    assert event is not None
    assert event.source == "zypp"
    assert event.extra["action"] == "install"
    assert event.extra["package"] == "zsh"
    assert event.extra["version"] == "5.9-160000.1.5"
    assert event.extra["repo"] == "repo-oss"


def test_zypp_padded_action_is_stripped(zypp):
    event = zypp.parse_line("2026-07-28 00:16:03|remove |vim|9.1.1418-16.1|aarch64|root@h|", 1)
    assert event is not None and event.extra["action"] == "remove"


def test_zypp_important_patch_is_warning(zypp):
    event = zypp.parse_line(
        "2026-07-28 00:15:52|patch  |openSUSE-Leap-16.0-1283|1|noarch|repo-oss"
        "|important|security|not-needed|applied|",
        1,
    )
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["category"] == "security"


def test_zypp_moderate_patch_is_info(zypp):
    event = zypp.parse_line(
        "2026-07-28 00:15:52|patch  |openSUSE-Leap-16.0-1215|1|noarch|repo-oss"
        "|moderate|recommended|not-needed|applied|",
        1,
    )
    assert event is not None and event.severity == Severity.INFO


def test_zypp_skips_comments_and_unknown_actions(zypp):
    assert zypp.parse_line("# zypp history", 1) is None
    assert zypp.parse_line("2026-07-28 00:15:52|notanaction|x|", 1) is None
    assert zypp.parse_line("2026-07-28 00:15:52 not pipe delimited", 1) is None


def test_zypp_fixture_detects_and_parses(fixtures_dir, zypp):
    path = fixtures_dir / "zypp_history.log"
    lines = _lines(fixtures_dir, "zypp_history.log")
    assert detect_parser(path, lines).FORMAT_NAME == "zypp-history"
    parsed = [zypp.parse_line(ln, i) for i, ln in enumerate(lines)]
    # Every line but the leading "#" comment is a record.
    assert sum(1 for e in parsed if e is not None) == len(lines) - 1


# ------------------------------------------------------------ macOS install


@pytest.fixture
def macos():
    return MacOSInstallParser()


def test_macos_short_offset_is_padded(macos):
    event = macos.parse_line(
        "2026-07-27 16:16:24+10 host softwareupdated[25464]: Periodic action called", 1
    )
    assert event is not None
    assert event.source == "softwareupdated"
    assert event.extra["pid"] == "25464"
    assert event.timestamp is not None
    assert event.timestamp.utcoffset().total_seconds() == 10 * 3600


def test_macos_selector_name_is_not_an_error(macos):
    """`_buildInstallPlanReturningError:` is a routine progress line."""
    event = macos.parse_line(
        "2026-07-27 16:16:27+10 host installer[9001]: "
        "-[IFDInstallController(Private) _buildInstallPlanReturningError:]: location = x",
        1,
    )
    assert event is not None and event.severity == Severity.INFO


def test_macos_routine_installer_errors_are_info(macos):
    # A real 258-day install.log (2026-10-20): thousands of these, zero failed
    # installs; graded as errors they made 67 false "error bursts".
    for msg in ("Error getting application status",
                "Package Authoring: error running installation-check script: TypeError: "
                "null is not an object (evaluating 'cpuFeatures.split')",
                "Failed to get bridge device",
                "SUOSUServiceDaemon: Failed to install product keys tonight: ("):
        event = macos.parse_line(f"2026-07-27 16:16:28+10 host installd[452]: {msg}", 1)
        assert event is not None and event.severity == Severity.INFO, msg


def test_macos_install_failure_is_an_error(macos):
    event = macos.parse_line(
        "2026-07-27 16:16:28+10 host installd[452]: PackageKit: Install Failed: "
        "Error Domain=PKInstallErrorDomain Code=112", 1)
    assert event is not None and event.severity == Severity.ERROR


def test_macos_program_names_with_spaces_and_rfc3164_lines_parse(macos):
    spaced = macos.parse_line(
        "2026-03-26 04:34:13+05:30 host Language Chooser[312]: set language", 1)
    assert spaced is not None and spaced.source == "Language Chooser"
    old = macos.parse_line("May 27 12:36:43 localhost powerd[53]: powerd process is started", 2)
    assert old is not None and old.source == "powerd" and old.timestamp is not None


def test_macos_skipping_is_a_warning(macos):
    event = macos.parse_line(
        "2026-07-27 16:16:29+10 host softwareupdated[25464]: Skipping update on battery", 1
    )
    assert event is not None and event.severity == Severity.WARNING


def test_macos_folds_indented_plist_dumps(fixtures_dir, macos):
    lines = _lines(fixtures_dir, "macos_install.log")
    events = list(macos.parse_stream(lines))
    # Two indented continuation lines are folded, not dropped.
    assert macos.meta_lines == 2
    assert len(events) == len(lines) - 2
    assert any("SUOSUProduct" in e.message for e in events)


def test_macos_fixture_detects(fixtures_dir):
    path = fixtures_dir / "macos_install.log"
    lines = _lines(fixtures_dir, "macos_install.log")
    assert detect_parser(path, lines).FORMAT_NAME == "macos-install"


def test_macos_does_not_claim_rfc3164_syslog():
    syslog = ["Jul 28 00:03:02 host syslogd[365]: ASL Sender Statistics"] * 5
    assert not MacOSInstallParser.can_parse(None, syslog)


def test_zypp_real_sles15sp7_annotation_lines_fold_into_records():
    """SLES 15 SP7 (real GCP image, 2026-10-13): most of the history is
    "#"-prefixed rpm output. Treated as unparsed, coverage fell to 602/3000 and
    the file went to generic; folded, every line after the first record counts."""
    from logcrux.parsers.registry import detect_parser
    from logcrux.parsers.zypp import ZyppHistoryParser

    fixtures = Path(__file__).parent.parent.parent / "fixtures"
    lines = (fixtures / "zypp_history_sles15sp7.log").read_text().splitlines()
    p = ZyppHistoryParser()
    events = list(p.parse_stream(iter(lines)))
    non_blank = sum(1 for ln in lines if ln.strip())
    first = next(i for i, ln in enumerate(lines) if ln and not ln.startswith("#"))
    assert len(events) + p.meta_lines == non_blank - first
    assert (len(events) + p.meta_lines) / non_blank >= ZyppHistoryParser.MIN_COVERAGE
    found = detect_parser(Path("/var/log/zypp/history"), lines[:20])
    assert isinstance(found, ZyppHistoryParser)
