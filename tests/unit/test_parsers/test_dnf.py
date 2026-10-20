"""dnf 4 log (/var/log/dnf.log, dnf.rpm.log) — real CentOS Stream 10 capture.

RHEL 10.2, AlmaLinux 10.2 and CentOS Stream 10 all still run dnf 4 (measured on
GCP VMs, 2026-10-13); dnf5 is Fedora 41+ only. Before DnfParser, dnf.log was
routed by name to `yum`, matched 0 lines and fell to generic.
"""
from pathlib import Path

from logcrux.models import Severity
from logcrux.parsers.dnf5 import Dnf5Parser, DnfParser
from logcrux.parsers.registry import detect_parser
from logcrux.parsers.yum import YumParser

FIX = Path(__file__).parent.parent.parent / "fixtures"


def _lines(name):
    return (FIX / name).read_text().splitlines()


def test_detects_dnf_log_by_name_and_content():
    lines = _lines("dnf4_centos_stream10.log")
    assert isinstance(detect_parser(Path("/var/log/dnf.log"), lines[:20]), DnfParser)
    assert isinstance(detect_parser(None, lines[:20]), DnfParser)
    assert isinstance(detect_parser(Path("/var/log/dnf.rpm.log"),
                                    _lines("dnf4_rpm_centos_stream10.log")[:20]), DnfParser)


def test_yum_no_longer_claims_dnf_log_by_name():
    lines = _lines("dnf4_centos_stream10.log")[:20]
    assert not YumParser.can_parse(Path("/var/log/dnf.log"), lines)


def test_dnf5_does_not_claim_dnf4_lines():
    assert not Dnf5Parser.can_parse(None, _lines("dnf4_centos_stream10.log")[:20])


def test_every_line_is_parsed_or_folded():
    lines = _lines("dnf4_centos_stream10.log")
    p = DnfParser()
    events = list(p.parse_stream(iter(lines)))
    assert len(events) + p.meta_lines == sum(1 for ln in lines if ln.strip())
    # The transaction table folds into the INFO record that introduces it.
    assert any("Installing:" in e.message for e in events)


def test_gpg_key_import_is_not_critical():
    events = list(DnfParser().parse_stream(iter(_lines("dnf4_centos_stream10.log"))))
    gpg = [e for e in events if e.message.startswith("Importing GPG key")]
    assert gpg and all(e.severity == Severity.INFO for e in gpg)
    assert not any(e.severity == Severity.CRITICAL for e in events)


def test_scriptlet_failure_is_an_error():
    events = list(DnfParser().parse_stream(iter(_lines("dnf4_rpm_centos_stream10.log"))))
    errs = [e for e in events if "Error in POSTIN scriptlet" in e.message]
    assert errs and all(e.severity == Severity.ERROR for e in errs)
    assert {e.extra["level"] for e in events} >= {"SUBDEBUG"}


def test_failed_command_is_a_job_outcome():
    """Real RHEL 8.10 dnf.log of `dnf install` of a package that doesn't exist:
    the failure is a single "CRITICAL Error: ..." record (GCP, 2026-10-13)."""
    from logcrux.analysis.anomaly import analyze_job_outcomes

    events = list(DnfParser().parse_stream(iter(_lines("dnf4_install_failure_rhel8.log"))))
    failed = [e for e in events if e.extra.get("outcome") == "failed"]
    assert len(failed) == 1
    assert failed[0].extra["detail"] == "Unable to find a match: lc-no-such-package-xyz"
    sig = analyze_job_outcomes(events)
    assert sig and sig[0].kind == "job_failure"
