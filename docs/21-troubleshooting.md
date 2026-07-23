# Troubleshooting

Common issues and solutions when using logcrux.

## Installation & Setup

### Issue: `pip install` Fails

```
ERROR: Could not find a version that satisfies the requirement...
```

**Solution:**
1. Ensure Python 3.11+: `python --version`. On distros whose system Python is
   older (Amazon Linux 2023, RHEL 9, Ubuntu 22.04 all default to 3.9-3.10),
   either install a newer interpreter (`sudo dnf install python3.11` /
   `sudo apt install python3.11`) or use `uv tool install logcrux` /
   `uvx logcrux`, which fetches a matching Python automatically.
2. Upgrade pip: `pip install --upgrade pip`
3. Try with `--no-cache-dir`: `pip install --no-cache-dir -e ".[dev]"`

### Issue: `externally-managed-environment` (pip)

```
error: externally-managed-environment
```

**Cause:** PEP 668, on Ubuntu, Debian, and Fedora — the system Python refuses
a global `pip install`.

**Solution:** Install into a venv instead, or use `uv tool install logcrux` /
`pipx install logcrux`, which avoid this automatically.

### Issue: `command not found: uv` (right after installing it)

**Cause:** The `uv` installer puts the binary in `~/.local/bin`, which isn't
on `PATH` yet in the current shell.

**Solution:**
```bash
export PATH="$HOME/.local/bin:$PATH"
# or just restart the shell
```

### Issue: `uv` installer fails with a missing tar/gzip

```
ERROR: need 'tar' (command not found)
```

**Cause:** The `uv` install script needs `tar` and `gzip`. Minimal
`amazonlinux:2023` and `opensuse/leap` base images don't ship them (Fedora
and the base RHEL images already include `tar`).

**Solution:**
```bash
sudo dnf install -y tar gzip      # or: sudo zypper install -y tar gzip
```

### Issue: No onnxruntime wheel / musl build (Alpine)

```
No matching distribution found for onnxruntime>=1.18       # pip
no wheels with a matching platform tag (musllinux_...)     # uv
```

**Cause:** Alpine or another musl-based image. onnxruntime doesn't publish
wheels for musl at any Python version — not fixable in place.

**Solution:** Switch to a glibc base image (Debian, Ubuntu, Fedora, or a
RHEL-family distro), or analyze the container's logs from outside it:
```bash
docker logs <container> | logcrux
```

### Issue: `uv` silently picked a musl build on a glibc distro

```
$ uv --version
uv 0.x.x (...-unknown-linux-musl)
```

**Cause:** Your glibc is older than 2.28 (RHEL 7 / CentOS 7 at 2.17, Amazon
Linux 2 at 2.26, Ubuntu 18.04 at 2.27), so `uv` fell back to its musl
binary — and no onnxruntime musl wheel exists (install may also fail trying
to build onnxruntime from source with `linker 'cc' not found`).

**Solution:** Check with `ldd --version`. Debian 10 (buster, glibc 2.28) is
the first version that works; RHEL/Rocky/AlmaLinux 8+, Ubuntu 20.04+, Debian
10+, Amazon Linux 2023, any current Fedora, and openSUSE Leap 15.3+/SLES 15
SP3+ all clear the floor. Below it, run logcrux from outside the old host
instead:
```bash
ssh oldbox 'cat /var/log/secure' | logcrux
# or a sidecar container on a glibc 2.28+ base (e.g. debian:12-slim)
# with the old host's log directory mounted in
```

### Issue: `python3: command not found` / Python too old (RHEL-family, openSUSE)

**Cause:** Rocky Linux, AlmaLinux, and Amazon Linux 2023 default to Python
3.9; openSUSE Leap defaults to 3.6. logcrux needs 3.11+.

**Solution:** `uv tool install logcrux` sidesteps this entirely, since it
supplies its own Python. For the `pip` path, install 3.11 explicitly first:
```bash
# Rocky / AlmaLinux / Amazon Linux 2023
sudo dnf install -y python3.11 python3.11-pip
python3.11 -m venv ~/.venvs/logcrux && ~/.venvs/logcrux/bin/pip install logcrux

# openSUSE Leap 15.6
sudo zypper install -y python311 python311-pip
python3.11 -m venv ~/.venvs/logcrux && ~/.venvs/logcrux/bin/pip install logcrux
```

### Issue: ONNX Models Not Found

```
Traceback: ONNX model not found at .../classifier.onnx
```

**Symptom:** `logcrux/inference/models/` is missing or the `.onnx` files are
absent/truncated. The models (~22MB each, INT8-quantized) are committed
directly in the repo, so this usually means a shallow/partial clone.

**Solution:**
```bash
# Verify
ls -lh logcrux/inference/models/*/model.onnx
# Should show ~22MB files each

# If missing, re-clone the repo
git clone https://github.com/ravipatip/logcrux.git
```

If the models are genuinely unavailable, logcrux still runs — statistical
analysis works fully, AI classification is just disabled (with a warning).

## File & Permissions

### Issue: Permission Denied

```
Error: Permission denied: /var/log/syslog
```

**Solution:**
```bash
# Check permissions
ls -la /var/log/syslog

# Run with sudo
sudo logcrux /var/log/syslog

# Or grant user read permission
sudo usermod -aG adm $USER
# Log out and back in
```

### Issue: File Not Found

```
Error: Cannot read log file
  /var/log/myapp.log: No such file or directory
```

**Solution:**
1. Check file exists: `ls -la /var/log/myapp.log`
2. Use absolute path: `logcrux /var/log/myapp.log` (not `./myapp.log`)
3. Check spelling and path

### Issue: File Too Large

```
Error: File too large
  logcrux-state.db exceeds 2048 MB limit
```

**Solution:**
1. Check file size: `du -h /path/to/file`
2. Increase limit in config:
```yaml
security:
  max_file_size_mb: 5000
```
3. Or analyze last N lines only:
```bash
tail -n 100000 /large/log.txt | logcrux
```

## Parsing & Format Detection

### Issue: Wrong Parser Detected

```
Parsed with: nginx_access (but it's actually Apache!)
```

**Solution:**
1. Override format: `logcrux /var/log/access.log --format apache_access`
2. Check detection precision in `docs/06-supported-log-types.md`
3. Report issue if detection is systematically wrong

### Issue: Many Lines Skipped

```
Parsed: 100 events, Skipped: 5000 events
```

**Symptom:** Parser isn't matching most lines.

**Solution:**
1. Verify format: `head -20 /var/log/mylog.log`
2. Try forcing format: `logcrux /var/log/mylog.log --format syslog`
3. Check if file is mixed formats (e.g., syslog + application JSON)
4. If the source is a container log stream, check for a syslog `<PRI>`
   prefix or ANSI color codes first: both block detection entirely
   rather than just lowering coverage. See "Feeding logs correctly"
   below.

### Issue: Parser Not Found

```
Error: Unknown format: myformat
```

**Solution:**
1. Check supported formats: `logcrux --help | grep format`
2. See `docs/06-supported-log-types.md` for complete list
3. File a feature request for new format

### Feeding logs correctly

logcrux is only as good as the stream you hand it.

**One log format per invocation.** `docker logs` merges stdout and
stderr. If a service writes an access log to stdout and an error log
to stderr, the mixed stream defeats format auto-detection. Split them:

```bash
docker logs myapp 2>/dev/null > access.log   # stdout only
logcrux access.log
```

**Strip container syslog priority prefixes.** Containers logging via
syslog can prepend a `<PRI>`-style tag (e.g. `<134>`) that
file-oriented parsers reject:

```bash
docker logs myapp 2>&1 | sed -E 's/^<[0-9]+>//' | logcrux
```

**Strip ANSI color codes.** Some services colorize their own log
output; the escape sequences disrupt parsing:

```bash
docker logs myapp 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' | logcrux
```

**Turn on the severity you want detected.** Some services only log
auth failures at a raised verbosity level (MySQL's
`log_error_verbosity`, for example). If the source doesn't log an
event at error/warning severity, there's nothing to cluster.

Parsing and detection are separate: even when a dedicated parser
matches only a minority of lines, logcrux falls back to a generic
parser and can still catch incidents by content. `--verbose` shows the
fallback decision.

## Analysis & Detection

### Issue: No Anomalies Detected

```
Output: CLEAN — No anomalies detected
```

**When Expected:** Some issues in logs, but none detected.

**Solutions:**
1. **Lower thresholds:**
```bash
# Reduce burst multiplier in config
analysis:
  burst_multiplier: 2.0  # More sensitive
  spike_factor: 2.0
```

2. **Use --verbose to debug:**
```bash
logcrux /var/log/syslog --verbose
# Shows: "Burst analysis: found 0 signals"
```

3. **Lower classification threshold:**
```bash
logcrux /var/log/syslog --threshold 0.2  # More lenient
```

4. **Confirm the source logs at error/warning severity, not info.** Some
   services log events like failed logins at info level by default
   (MySQL, MongoDB); logcrux deliberately ignores info-level noise so a
   clean result is meaningful, and won't cluster what it never sees as
   an error. Raise the source's log verbosity if you need those events
   caught.

5. **Check baseline is reasonable:**
```bash
sqlite3 ~/.local/share/logcrux/state.db
> SELECT * FROM baselines WHERE format = 'syslog';
```

6. **Skip baseline if just started:**
```bash
logcrux /var/log/syslog --no-baseline
```

### Issue: Too Many False Positives

```
Output: CRITICAL level on what looks like normal operation
```

**Solutions:**
1. **Raise thresholds:**
```bash
logcrux /var/log/syslog --threshold 0.7
```

2. **Increase burst multiplier:**
```yaml
analysis:
  burst_multiplier: 5.0  # Only alert on 5x baseline
  spike_factor: 5.0
```

3. **Allow baseline to stabilize:**
   - Let system run normally for 24+ hours
   - Baseline will learn normal patterns
   - Alarms will become more meaningful

4. **Check if events are really anomalous:**
```bash
# View sample events
logcrux /var/log/syslog --verbose 2>&1 | head -50
```

## AI & Inference

### Issue: Models Not Loading

```
Warning: AI inference unavailable: ONNX models not found
Showing statistical findings only.
```

**Solution:** See [ONNX Models Not Found](#issue-onnx-models-not-found) above.

### Issue: All Incidents Classified as UNKNOWN

```
Category: UNKNOWN (0.15 confidence)
```

**Solution:**
1. **Lower threshold:**
```bash
logcrux /var/log/syslog --threshold 0.1
```

2. **Check model quality:**
```bash
# Verify large model files exist
ls -lh logcrux/inference/models/
```

3. **Report if systematic:** If the model files are missing/corrupted, see [ONNX Models Not Found](#issue-onnx-models-not-found) above.

### Issue: Inconsistent Classifications

```
Same logs → different categories on different runs
```

**Cause:** Randomness in inference (low confidence, near threshold).

**Solution:**
1. Increase threshold to only report high-confidence:
```bash
logcrux /var/log/syslog --threshold 0.6
```

2. Use only deterministic signals (no AI):
```yaml
inference:
  enabled: false
```

## State & Baseline

### Issue: Baseline Not Updating

```
Baseline unchanged across multiple analyses
```

**Cause:** `--no-baseline` flag or state.db not writable.

**Solution:**
```bash
# Check state DB permissions
ls -la ~/.local/share/logcrux/

# Fix permissions
chmod 700 ~/.local/share/logcrux/
chmod 600 ~/.local/share/logcrux/state.db

# Or delete to reset
rm ~/.local/share/logcrux/state.db
logcrux /var/log/syslog  # Creates new DB
```

### Issue: Database Locked

```
Error: Database is locked
```

**Cause:** Another logcrux process is writing.

**Solution:**
```bash
# Check for running processes
pgrep logcrux

# Kill any stray processes
killall logcrux

# Or use --no-baseline to skip state
logcrux /var/log/syslog --no-baseline
```

### Issue: State DB Corrupted

```
Error: Database disk image is malformed
```

**Solution:**
```bash
# Delete corrupted DB
rm ~/.local/share/logcrux/state.db

# logcrux will create fresh DB on next run
logcrux /var/log/syslog
```

## Performance

### Issue: Analysis Slow (>10 seconds)

**Symptom:** Analysis takes >10s for large logs.

**Solutions:**
1. **Analyze recent logs only:**
```bash
logcrux /var/log/syslog --last 1h
```

2. **Pipe instead of file:**
```bash
tail -n 10000 /var/log/syslog | logcrux
```

3. **Check for large parsed events:**
```bash
# Count events parsed
logcrux /var/log/syslog --verbose 2>&1 | grep "Parsed:"
```

### Issue: High Memory Usage

**Symptom:** logcrux uses >1GB RAM.

**Cause:** Loading very large log files into memory.

**Solutions:**
1. **Use --last flag:**
```bash
logcrux /var/log/syslog --last 1h  # Only recent
```

2. **Pipe from tail:**
```bash
tail -n 100000 /var/log/syslog | logcrux
```

3. **Increase system swap** (temporary):
```bash
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Output & Display

### Issue: No Output

```bash
$ logcrux /var/log/syslog
# (nothing printed)
```

**Cause:** Output buffering or error.

**Solution:**
```bash
# Force unbuffered output
stdbuf -oL logcrux /var/log/syslog

# Or use -u flag (Python unbuffered)
python -u -m logcrux /var/log/syslog

# Or check for errors
logcrux /var/log/syslog 2>&1 | cat
```

### Issue: Unicode Errors

```
Error: UnicodeDecodeError: 'utf-8' codec can't decode byte...
```

**Cause:** Log file has non-UTF-8 characters.

**Solution:**
```bash
# Convert file to UTF-8
iconv -f ISO-8859-1 -t UTF-8 /var/log/syslog > /tmp/syslog_utf8
logcrux /tmp/syslog_utf8

# Or strip non-UTF-8
sed 's/[^\x00-\x7F]//g' /var/log/syslog | logcrux
```

### Issue: Colors Not Showing

```
Output is black & white despite --color flag
```

**Cause:** Terminal doesn't support colors.

**Solution:**
1. **Force no colors:**
```yaml
output:
  color: false
```

2. **Or disable in CLI:**
```bash
logcrux /var/log/syslog --color=false  # (if CLI option added)
```

## Configuration

### Issue: Config File Not Found

```
Using default config (file not found)
```

**Check:**
```bash
# logcrux looks in order:
# 1. $LOGCRUX_CONFIG
# 2. ~/.config/logcrux/logcrux.yaml
# 3. /etc/logcrux/logcrux.yaml
# 4. Hardcoded defaults

# Create user config
mkdir -p ~/.config/logcrux
cat > ~/.config/logcrux/logcrux.yaml << 'EOF'
analysis:
  burst_multiplier: 3.0
EOF
```

### Issue: Config Not Applied

```
Config file exists but settings not used
```

**Solution:**
1. **Check YAML syntax:**
```bash
python -m yaml < ~/.config/logcrux/logcrux.yaml
# If error, fix YAML syntax
```

2. **Verify with --verbose:**
```bash
logcrux /var/log/syslog --verbose 2>&1 | grep -i config
```

3. **Use --config to force:**
```bash
logcrux /var/log/syslog --config /path/to/custom.yaml
```

## Debugging

### Enable Verbose Logging

```bash
logcrux /var/log/syslog --verbose
```

Shows:
- Parser detection decisions
- Analysis engine outputs
- Baseline operations
- Inference results

### Check Log Samples

```bash
head -100 /var/log/syslog | logcrux
```

Analyze just first 100 lines to test.

### Print Parsed Events

Add to code temporarily:
```python
# In cli.py after parsing
for event in parsed_events[:10]:
    print(event.model_dump_json(indent=2))
```

### Use Python REPL

```python
python
>>> from logcrux.parsers.registry import detect_parser
>>> from pathlib import Path
>>> 
>>> parser = detect_parser(Path("/var/log/syslog"), [])
>>> print(parser.FORMAT_NAME)
syslog
```

### Check Test Suite

```bash
# Run relevant tests
pytest tests/unit/test_parsers/ -v
pytest tests/integration/ -v -k "syslog"
```

## Getting Help

### File a Bug Report

```bash
# Gather diagnostics
logcrux /path/to/log --verbose > /tmp/logcrux.log 2>&1
logcrux --version
python --version
uname -a
```

Include:
- Log file sample (first 50 lines)
- Full verbose output
- Version information
- Expected vs actual behavior

### Check Documentation

- [Supported Log Types](./06-supported-log-types.md)
- [Configuration](./04-configuration.md)
- [Architecture](./02-architecture.md)

---

**Last Updated:** July 2026
