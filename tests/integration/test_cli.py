import json
import shutil
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from logcrux.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent.parent / "fixtures"


def _copy_to_tmp(fixture_name: str, tmp_path: Path) -> Path:
    """Copy fixture into /tmp/ so it's within the allowed /tmp/ path.

    On macOS, pytest's tmp_path resolves to /private/var/folders/... which is
    outside the security allow-list. We create a subdirectory under /tmp/
    instead, which resolves to /private/tmp/ and satisfies the check.
    """
    src = FIXTURES / fixture_name
    # Use a sub-directory of /tmp/ that is unique per tmp_path name
    safe_dir = Path(tempfile.mkdtemp(dir="/tmp"))
    dst = safe_dir / fixture_name
    shutil.copy(src, dst)
    return dst


def test_clean_log_exits_0(tmp_path):
    log = _copy_to_tmp("syslog_clean.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    assert result.exit_code == 0, f"exit={result.exit_code}\n{result.output}"


def test_auth_bruteforce_exits_3_or_4(tmp_path):
    log = _copy_to_tmp("auth_bruteforce.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    # Statistical analysis alone (no ONNX needed) detects auth_failure_cluster
    # from 19 "Failed password" lines — exit 0 means statistical analysis broke.
    assert result.exit_code in (3, 4), f"exit={result.exit_code}\n{result.output}"


def test_oom_log_exits_3_or_4(tmp_path):
    log = _copy_to_tmp("syslog_oom.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    # Statistical analysis alone detects oom_event from "Out of memory" /
    # "oom-kill" keywords — exit 0 means statistical analysis broke.
    assert result.exit_code in (3, 4), f"exit={result.exit_code}\n{result.output}"


def test_json_output_is_valid(tmp_path):
    log = _copy_to_tmp("syslog_clean.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    for key in ("level", "title", "findings", "confidence", "category",
                "analysis_id", "parser_format", "parsed_count"):
        assert key in data, f"missing key: {key}"
    assert data["level"] == "CLEAN"
    assert len(data["analysis_id"]) == 36  # UUID
    assert data["parsed_count"] > 0


def test_stdin_pipe():
    log_content = (FIXTURES / "auth_bruteforce.log").read_text()
    result = runner.invoke(app, ["--no-baseline", "--json"], input=log_content)
    # Auth bruteforce fixture has 19 failures — statistical analysis must fire
    assert result.exit_code in (3, 4), result.output
    data = json.loads(result.output)
    assert data["parsed_count"] > 0, "stdin was not read"


def test_misdetected_log_falls_back_to_generic(tmp_path):
    # Sample (first 20 lines) is pure cron so detection picks the cron parser,
    # but the bulk of the file is app logs the cron parser can't read. The tool
    # must not silently drop them — it falls back to the generic parser and
    # recovers every non-blank line.
    lines = [
        f"May 19 10:{i:02d}:01 host CRON[{i}]: pam_unix(cron:session): session opened"
        for i in range(20)
    ]
    lines += [
        f"2026-06-20T11:{i:02d}:00 myapp ERROR database connection refused"
        for i in range(40)
    ]
    log = tmp_path / "mixed.log"
    log.write_text("\n".join(lines) + "\n")
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    assert result.exit_code in (0, 3, 4), result.output
    data = json.loads(result.output)
    # 0.9 fell back to generic for the whole file; now each part keeps a parser
    # that understands it (cron+syslog) — either way no line may be lost.
    assert data["parser_format"] != "cron", data
    assert data["parsed_count"] == 60, data
    assert data["skipped_count"] == 0, data


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.10.0" in result.output


def test_invalid_path_exits_2():
    result = runner.invoke(app, ["/nonexistent/path/to/log.log"])
    assert result.exit_code == 2


def test_nginx_access_log(tmp_path):
    log = _copy_to_tmp("nginx_access.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    assert result.exit_code in (0, 3, 4), result.output


def test_apache_error_log(tmp_path):
    log = _copy_to_tmp("apache_error.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    assert result.exit_code in (0, 3, 4), result.output


def test_journald_log(tmp_path):
    log = _copy_to_tmp("journald_export.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    assert result.exit_code in (0, 3, 4), result.output


def test_squid_native_log(tmp_path):
    log = _copy_to_tmp("squid_native.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    assert result.exit_code in (0, 3, 4), f"exit={result.exit_code}\n{result.output}"
    # squid_native.log has 12 TCP_DENIED and 2 CONNECT to port 22 — expect proxy signals
    assert result.exit_code in (3, 4) or "no incidents" in result.output.lower()


def test_squid_clf_log(tmp_path):
    log = _copy_to_tmp("squid_clf.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    assert result.exit_code in (0, 3, 4), f"exit={result.exit_code}\n{result.output}"


def test_squid_native_json_output(tmp_path):
    log = _copy_to_tmp("squid_native.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    assert result.exit_code in (0, 3, 4), result.output
    data = json.loads(result.output)
    assert "level" in data
    assert "findings" in data


def test_gzipped_log_is_decompressed(tmp_path):
    # Rotated logs are gzipped (syslog.1.gz). Reading the compressed bytes as
    # text would parse garbage and report a misleading result, so the CLI must
    # transparently decompress and recover the same events as the plain file.
    import gzip

    src = FIXTURES / "auth_bruteforce.log"
    safe_dir = Path(tempfile.mkdtemp(dir="/tmp"))
    gz = safe_dir / "auth_bruteforce.log.gz"
    with open(src, "rb") as fin, gzip.open(gz, "wb") as fout:
        fout.write(fin.read())

    result = runner.invoke(app, [str(gz), "--no-baseline"])
    assert result.exit_code in (0, 3, 4), f"exit={result.exit_code}\n{result.output}"
    # The plain file has many lines; a garbage parse of gzip bytes yields ~1.
    expected = sum(1 for line in src.read_text().splitlines() if line.strip())
    assert f"Analyzed {expected:,}" in result.output, result.output


def test_truncated_gzip_recovers_prefix(tmp_path):
    # A rotated log truncated mid-stream (crash, partial copy) must not abort
    # the run: the decompressable prefix is analyzed with a loud warning.
    import gzip

    src = FIXTURES / "auth_bruteforce.log"
    safe_dir = Path(tempfile.mkdtemp(dir="/tmp"))
    gz = safe_dir / "auth.log.1.gz"
    with open(src, "rb") as fin, gzip.open(gz, "wb", compresslevel=0) as fout:
        fout.write(fin.read() * 50)
    data = gz.read_bytes()
    gz.write_bytes(data[: len(data) // 2])

    result = runner.invoke(app, [str(gz), "--no-baseline"])
    assert result.exit_code in (0, 3, 4), f"exit={result.exit_code}\n{result.output}"
    combined = result.output + (result.stderr or "")
    assert "truncated or corrupt" in combined, combined


def test_unrecoverable_gzip_exits_2():
    safe_dir = Path(tempfile.mkdtemp(dir="/tmp"))
    gz = safe_dir / "bogus.log.gz"
    gz.write_bytes(b"\x1f\x8b")  # gzip magic, nothing else
    result = runner.invoke(app, [str(gz), "--no-baseline"])
    assert result.exit_code == 2, f"exit={result.exit_code}\n{result.output}"


def test_unknown_format_is_clean_error(tmp_path):
    log = _copy_to_tmp("auth_bruteforce.log", tmp_path)
    result = runner.invoke(app, [str(log), "--format", "nosuch"])
    assert result.exit_code == 1, f"exit={result.exit_code}\n{result.output}"
    combined = result.output + (result.stderr or "")
    assert "Unknown format" in combined and "Traceback" not in combined, combined


def test_format_alias_nginx(tmp_path):
    log = _copy_to_tmp("nginx_access.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline", "--format", "nginx", "--json"])
    assert result.exit_code in (0, 3, 4), f"exit={result.exit_code}\n{result.output}"
    assert json.loads(result.output)["parser_format"] == "nginx-access"


def test_bad_config_is_clean_error(tmp_path):
    log = _copy_to_tmp("auth_bruteforce.log", tmp_path)
    cfg = Path(tempfile.mkdtemp(dir="/tmp")) / "bad.yaml"
    cfg.write_text("inference:\n  threshold: 5.0\n")
    result = runner.invoke(app, [str(log), "--config", str(cfg)])
    assert result.exit_code == 1, f"exit={result.exit_code}\n{result.output}"
    combined = result.output + (result.stderr or "")
    assert "Invalid config" in combined and "Traceback" not in combined, combined


def test_utf16_log_is_decoded(tmp_path):
    # Windows-exported logs are routinely UTF-16 (with or without BOM). Decoded
    # as UTF-8 they become NUL-riddled garbage that "parses" generically and a
    # brute-force log reports CLEAN — a silent false negative.
    src = FIXTURES / "auth_bruteforce.log"
    safe_dir = Path(tempfile.mkdtemp(dir="/tmp"))
    for name, enc in (("bom.log", "utf-16"), ("nobom.log", "utf-16-le")):
        target = safe_dir / name
        target.write_text(src.read_text(), encoding=enc)
        result = runner.invoke(app, [str(target), "--no-baseline", "--json"])
        data = json.loads(result.output)
        assert data["parser_format"] == "secure", (name, data["parser_format"])
        assert data["level"] != "CLEAN", name


def test_utf8_bom_does_not_cost_first_line(tmp_path):
    src = FIXTURES / "auth_bruteforce.log"
    safe_dir = Path(tempfile.mkdtemp(dir="/tmp"))
    target = safe_dir / "bom.log"
    target.write_bytes(b"\xef\xbb\xbf" + src.read_bytes())
    result = runner.invoke(app, [str(target), "--no-baseline", "--json"])
    expected = sum(1 for line in src.read_text().splitlines() if line.strip())
    assert json.loads(result.output)["parsed_count"] == expected


def test_huge_single_line_completes_quickly(tmp_path):
    # A multi-MB line (minified JSON, dumped payload) once stalled format
    # detection for minutes in a backtracking logfmt regex (O(n²) findall).
    import time as _time

    safe_dir = Path(tempfile.mkdtemp(dir="/tmp"))
    target = safe_dir / "huge.log"
    target.write_text(
        "2026-07-12T10:00:01Z host app[1]: ERROR payload " + "x" * 2_000_000 + "\n"
        "2026-07-12T10:00:02Z host app[1]: INFO ok\n"
    )
    start = _time.monotonic()
    result = runner.invoke(app, [str(target), "--no-baseline", "--json"])
    assert _time.monotonic() - start < 15, "huge line stalled the pipeline"
    assert json.loads(result.output)["parsed_count"] == 2


def test_small_iis_log_keeps_iis_parser_and_severity(tmp_path):
    # Regression: the 3 "#Software/#Version/#Fields" header lines pushed a small
    # IIS log below the 60% fallback coverage threshold, so the generic parser
    # took over and lost the sc-status→severity mapping (a 500 became INFO).
    # Header lines are structure the parser consumed, not data loss.
    log = _copy_to_tmp("iis.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    assert result.exit_code in (0, 3, 4), result.output
    data = json.loads(result.output)
    assert data["parser_format"] == "iis", data
    assert data["skipped_count"] == 0, data


def test_zeek_directive_headers_not_reported_unparsed(tmp_path):
    log = _copy_to_tmp("zeek.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    assert result.exit_code in (0, 3, 4), result.output
    data = json.loads(result.output)
    assert data["parser_format"] == "zeek", data
    assert data["skipped_count"] == 0, data


def test_oracle_timestamp_lines_not_reported_unparsed(tmp_path):
    log = _copy_to_tmp("oracle.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    assert result.exit_code in (0, 3, 4), result.output
    data = json.loads(result.output)
    assert data["parser_format"] == "oracle", data
    assert data["skipped_count"] == 0, data


def test_mysql_slow_log_block_lines_not_reported_unparsed(tmp_path):
    log = _copy_to_tmp("mysql_slow.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    assert result.exit_code in (0, 3, 4), result.output
    data = json.loads(result.output)
    assert data["parser_format"] == "mysql", data
    assert data["skipped_count"] == 0, data


def test_kernel_log_with_apparmor_line_uses_kernel_parser(tmp_path):
    log = _copy_to_tmp("kernel.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    assert result.exit_code in (0, 3, 4), result.output
    data = json.loads(result.output)
    assert data["parser_format"] == "kernel", data


def test_python_dash_m_entrypoint(tmp_path):
    # `python -m logcrux.cli file.log` must behave like the `logcrux` binary,
    # not silently exit 0 with no output.
    import subprocess
    import sys

    log = _copy_to_tmp("syslog_clean.log", tmp_path)
    proc = subprocess.run(  # noqa: S603 — fixed args, our own interpreter
        [sys.executable, "-m", "logcrux.cli", str(log), "--no-baseline", "--json"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["parsed_count"] > 0


def test_json_findings_carry_evidence(tmp_path):
    log = _copy_to_tmp("auth_bruteforce.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    data = json.loads(result.output)
    assert data["schema_version"] == "2"
    f = data["findings"][0]
    assert f["kind"] == "auth_failure_cluster"
    assert f["count"] >= 10 and f["first_seen"]
    assert any(s["label"] == "source" for s in f["subjects"])
    ev = f["evidence"][0]
    assert ev["line"] >= 1 and ev["text"] in log.read_text()
    assert data["coverage"]["lines"] > 0 and data["severity_counts"]


def test_text_output_shows_evidence_line_numbers(tmp_path):
    log = _copy_to_tmp("auth_bruteforce.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    assert "line " in result.output and "source:" in result.output
    assert "Checked" in result.output


def test_empty_input_is_flagged_not_silently_clean(tmp_path):
    safe_dir = Path(tempfile.mkdtemp(dir="/tmp"))
    log = safe_dir / "empty.log"
    log.write_text("")
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    data = json.loads(result.output)
    assert data["level"] == "CLEAN"
    assert any("empty" in w for w in data["warnings"])
    result = runner.invoke(app, [str(log), "--no-baseline"])
    assert "Nothing to analyze" in result.output


def test_clean_text_says_what_was_checked(tmp_path):
    log = _copy_to_tmp("syslog_clean.log", tmp_path)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    assert result.exit_code == 0
    assert "Checked" in result.output and "syslog" in result.output


def _tmpdir() -> Path:
    return Path(tempfile.mkdtemp(dir="/tmp"))


def test_binary_file_is_refused_not_reported_clean():
    d = _tmpdir()
    wtmp = d / "wtmp"
    wtmp.write_bytes(bytes(range(256)) * 40)
    result = runner.invoke(app, [str(wtmp), "--no-baseline"])
    assert result.exit_code == 2, result.output
    assert "binary" in result.output and "last -f" in result.output


def test_utf16_is_text_not_binary():
    d = _tmpdir()
    log = d / "app.log"
    log.write_text("2026-10-13 08:00:00 ERROR boom\n" * 3, encoding="utf-16")
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    assert json.loads(result.output)["parsed_count"] == 3


def test_nul_padded_log_still_parses():
    src = (FIXTURES / "auth_bruteforce.log").read_text()
    d = _tmpdir()
    log = d / "secure"
    log.write_text(src + "\x00" * 4096)
    result = runner.invoke(app, [str(log), "--no-baseline", "--json"])
    data = json.loads(result.output)
    assert data["category"] == "auth_brute_force", data


def test_several_files_and_a_directory():
    d = _tmpdir()
    shutil.copy(FIXTURES / "auth_bruteforce.log", d / "auth.log")
    shutil.copy(FIXTURES / "syslog_clean.log", d / "syslog")
    (d / "wtmp").write_bytes(bytes(range(256)) * 40)
    result = runner.invoke(app, [str(d), "--no-baseline"])
    assert result.exit_code in (3, 4), result.output
    assert "2 file(s)" in result.output and "auth.log" in result.output
    assert "wtmp" in result.output  # reported as skipped, not analysed
    result = runner.invoke(app, [str(d / "syslog"), str(d / "auth.log"),
                                 "--no-baseline", "--json"])
    data = json.loads(result.output)
    assert isinstance(data, list) and len(data) == 2
    assert {x["level"] for x in data} >= {"CLEAN"}


def test_all_clean_directory_exits_0():
    d = _tmpdir()
    shutil.copy(FIXTURES / "syslog_clean.log", d / "a.log")
    shutil.copy(FIXTURES / "syslog_clean.log", d / "b.log")
    result = runner.invoke(app, [str(d), "--no-baseline"])
    assert result.exit_code == 0, result.output


def test_missing_file_among_several_is_skipped():
    d = _tmpdir()
    shutil.copy(FIXTURES / "syslog_clean.log", d / "a.log")
    result = runner.invoke(app, [str(d / "a.log"), str(d / "nope.log"), "--no-baseline"])
    assert result.exit_code == 0, result.output
    assert "nope.log" in result.output


def test_last_reads_naive_timestamps_as_local_time(monkeypatch):
    import time as _time
    from datetime import datetime, timedelta

    for tz in ("Australia/Sydney", "America/Los_Angeles"):
        monkeypatch.setenv("TZ", tz)
        _time.tzset()
        now = datetime.now()
        d = _tmpdir()
        log = d / "app.log"
        log.write_text("".join(
            (now - timedelta(minutes=m)).strftime("%b %d %H:%M:%S") + f" host app[1]: tick {m}\n"
            for m in range(180, 0, -1)))
        result = runner.invoke(app, [str(log), "--last", "1h", "--no-baseline", "--json"])
        assert 55 <= json.loads(result.output)["parsed_count"] <= 61, (tz, result.output[:300])
    monkeypatch.delenv("TZ")
    _time.tzset()


def test_doctor_reports_the_install():
    result = runner.invoke(app, ["--doctor"])
    assert result.exit_code == 0, result.output
    for key in ("python", "parsers", "ai models", "state db"):
        assert key in result.output


def test_a_file_named_doctor_is_still_analysed():
    d = _tmpdir()
    shutil.copy(FIXTURES / "auth_bruteforce.log", d / "doctor")
    result = runner.invoke(app, [str(d / "doctor"), "--no-baseline", "--json"])
    assert json.loads(result.output)["category"] == "auth_brute_force"


def test_journalctl_permission_notice_is_flagged():
    notice = ("Hint: You are currently not seeing messages from other users and the system.\n"
              "      Users in groups 'adm', 'systemd-journal' can see all messages.\n"
              "      Pass -q to turn off this notice.\n"
              "No journal files were opened due to insufficient permissions.\n")
    result = runner.invoke(app, ["--no-baseline", "--json"], input=notice)
    data = json.loads(result.output)
    assert any("permission notice" in w for w in data["warnings"]), data["warnings"]


def test_unreadable_file_says_what_to_do(tmp_path):
    import os
    if os.geteuid() == 0:
        return  # root reads everything
    d = _tmpdir()
    log = d / "auth.log"
    log.write_text("x\n")
    log.chmod(0)
    result = runner.invoke(app, [str(log), "--no-baseline"])
    assert result.exit_code == 2
    assert "Permission denied" in result.output and "sudo" in result.output
    assert "Invalid value" not in result.output
    log.chmod(0o644)


def test_directory_members_keep_the_named_path():
    d = _tmpdir()
    target = _tmpdir() / "README.logs"
    target.write_text("plain text\n")
    (d / "README").symlink_to(target)
    shutil.copy(FIXTURES / "syslog_clean.log", d / "syslog")
    result = runner.invoke(app, [str(d), "--no-baseline", "--json"])
    paths = {x["log_path"] for x in json.loads(result.output)}
    assert str(d / "README") in paths, paths


def test_each_file_footer_counts_its_own_incidents():
    d = _tmpdir()
    shutil.copy(FIXTURES / "auth_bruteforce.log", d / "a-auth.log")
    shutil.copy(FIXTURES / "syslog_clean.log", d / "b-clean.log")
    result = runner.invoke(app, [str(d), "--no-baseline", "--verbose"])
    footers = [ln for ln in result.output.splitlines() if ln.startswith("Analyzed")]
    assert len(footers) == 2 and "0 incident(s)" in footers[1] and "0 incident" not in footers[0]


def test_dash_means_stdin():
    log_content = (FIXTURES / "auth_bruteforce.log").read_text()
    result = runner.invoke(app, ["-", "--no-baseline", "--json"], input=log_content)
    assert json.loads(result.output)["log_path"] == "<stdin>"


def test_fail_on_controls_the_exit_code():
    log = FIXTURES / "auth_bruteforce.log"   # a WARNING
    assert runner.invoke(app, [str(log), "--no-baseline"]).exit_code == 3
    assert runner.invoke(app, [str(log), "--no-baseline", "--fail-on", "critical"]).exit_code == 0
    assert runner.invoke(app, [str(log), "--no-baseline", "--fail-on", "never"]).exit_code == 0
    oom = FIXTURES / "syslog_oom.log"        # CRITICAL
    assert runner.invoke(app, [str(oom), "--no-baseline", "--fail-on", "critical"]).exit_code == 4
    assert runner.invoke(app, [str(log), "--fail-on", "bogus"]).exit_code == 1


def test_directory_run_skips_documents_but_named_files_are_analysed():
    d = _tmpdir()
    shutil.copy(FIXTURES / "syslog_clean.log", d / "syslog")
    (d / "NOTES.md").write_text("Too many open files\n" * 30)
    result = runner.invoke(app, [str(d), "--no-baseline", "--json"])
    assert {Path(x["log_path"]).name for x in json.loads(result.output)} == {"syslog"}
    result = runner.invoke(app, [str(d / "NOTES.md"), "--no-baseline", "--json"])
    assert json.loads(result.output)["parsed_count"] == 30
