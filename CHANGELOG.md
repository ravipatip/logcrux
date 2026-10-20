# Changelog

All notable changes to logcrux are documented in this file.

## [0.10.0] - 2026-10-20

Driven by a test campaign on 12 real Linux distributions (Debian, Ubuntu x86_64
and arm64, RHEL, Rocky, AlmaLinux, CentOS Stream, SLES, openSUSE) with faults
induced on real systems. On that corpus 0.9.0 detected 64% of faults; most of
the misses were single-line failures that every detector, needing a burst,
could not see.

### Added
- **Every finding carries its evidence.** What it is about (source IPs and
  users of an auth attack, the process the OOM killer chose, the unit that
  crashed, the HTTP status and path of a 5xx flood, or the recurring message
  of an error burst, each with counts), when it started and ended, and the
  actual log lines with their line numbers. JSON gains `schema_version` "2",
  per-finding `kind`, `count`, `first_seen`/`last_seen`, `subjects` and
  `evidence`, plus `coverage`, `time_range`, `severity_counts` and `warnings`.
- Every result says what was checked: format, how many lines parsed, the
  time span and the error/warning counts. A clean verdict says what it did
  not find; empty input says so instead of reporting a confident CLEAN.
- Several files, or a directory, in one run: `logcrux /var/log/nginx/` or
  `logcrux a.log b.log`. Each non-clean file gets its full report, then one
  table ranks every file; binary members (wtmp, `.journal`) are skipped and
  listed; exit code is the worst verdict. `--json` emits a list.
- `docker logs` of common images are understood. A stream that interleaves
  formats (nginx/httpd write access lines to stdout and errors to stderr,
  behind an entrypoint banner) is parsed line by line with the parsers that
  claim parts of it, the rest kept as generic events, instead of all-generic;
  a 502 flood is HTTP Overload again, not "Network Issue". Transport wrappers
  are stripped first: ANSI colours, syslog `<PRI>`, the `--timestamps`
  column of `docker logs`/`kubectl logs`, and `kubectl logs --prefix`.
- A process killed by its own unhandled exception is reported with the
  exception that killed it: a Python traceback that ends the log, node's
  crash trailer, `Exception in thread "main"`, a Go panic, a Rust panic on
  the main thread. JVM
  `OutOfMemoryError` is an OOM.
- Kubernetes: `ErrImagePull`/`ImagePullBackOff` is a configuration error
  naming the image and pod; crash-looping pods are named in `kubectl get
  events` / `describe`. A CLEAN result on a short log that stops on a fatal-
  sounding error shows that line ("Last line logged is an error") — the
  likely reason a container exited — without alarming on it.
- "Backend server down": haproxy servers still DOWN at the end of the log
  (and nginx "no live upstreams") lead the report, ahead of the 5xx flood.
- `--fail-on warning|critical|never` for CI gates; `logcrux -` reads stdin.
- `logcrux --doctor`: Python, platform, parser count, config, whether the
  AI models load (and how to fix it when onnxruntime is missing), state DB.
- Job-outcome detection: a backup job that fails (`Fatal:`) or completes with
  missing data is reported, quoting the tool's own reason. restic first.
- SELinux denials (`avc: denied ... permissive=0`) are reported as a
  configuration fault, naming what was denied, from audit.log or the journal.
- Parser `macos-unified`: `log show` output in its default, compact and
  syslog styles, using macOS's own level column. An idle Mac's 3-minute log
  was generic text spanning a week (dates inside folded plist lines) and a
  9,000-error false "burst"; it is now CLEAN over the right 3 minutes.
- New findings for classic sysadmin incidents: **resource limit reached**
  (file descriptors, process/fork limits, thread and connection limits),
  **TLS certificate rejected** (expired, untrusted, wrong name), and **mail
  rejected in bulk** (Postfix `NOQUEUE: reject` bursts, naming the client).
- No line is silently dropped any more: when the detected parser covers most
  but not all of a file, the rest are kept as generic events (an Apache
  "consider raising the MaxRequestWorkers setting" error was lost this way).
  Capacity limits (Apache MaxRequestWorkers, php-fpm pm.max_children,
  Postgres "too many clients") are resource-limit findings.
- Kubernetes: failing liveness/startup probes (container restarted) and
  repeated readiness failures are a "Health check failing" finding; a pod
  that cannot be scheduled for lack of node capacity is a resource limit.
- **System clock jumped** (chrony's jump detection or an offset >= 60 s) and
  a **package manager locked** by another run (zypper, apt) are reported.
- Parser `json`: any JSON-lines application log with a level and a message
  key (Python structlog, Go zap/slog/zerolog, logrus/loguru JSON, ...) gets
  real levels and timestamps instead of generic text; a structured logger's
  final fatal/critical record is reported as "Process exited after a fatal
  error".
- Parser `borg` (BorgBackup): wrong passphrase, missing repository, lock
  failures are job failures; an unreadable source is "completed with
  missing data".
- Authentication failures in wordings logcrux has no rule for are still
  counted: an auth noun (authentication, login, password, credentials) and a
  failure word (failed, denied, invalid, mismatch, ...) on one line. It found
  an 800-attempt nginx basic-auth brute force (`password mismatch`) that was
  only an unnamed error burst, with no other verdict changed in 3,646 logs.
- BIND "zone ... not loaded due to errors" is a config error; Samba
  "FAILED with error NT_STATUS_WRONG_PASSWORD" counts toward brute force
  (once per attempt, naming the user).
- Mosquitto "disconnected, not authorised" counts toward brute force;
  Prometheus/Alertmanager "Error loading config" is a config error.
- Keycloak `LOGIN_ERROR` events, OpenLDAP failed binds (`RESULT tag=97
  err=49`) and PHP `Fatal error: Uncaught ...` (via php-fpm) are detected;
  they were CLEAN. The crashing PHP script is named.
- Parser `kopia` (backup): a failed snapshot or repository connection is a
  job failure quoting kopia's reason (wrong password, missing source,
  repository gone) — each was one ERROR line and CLEAN.
- Tomcat: stack traces fold into their record (a startup failure fell to
  generic), a rejected `server.xml` is a config error; an uncaught
  `ConfigException` (Kafka) is a config error, not just a crash.
- Parsers: `dnf` (dnf 4 — still the package manager on RHEL/AlmaLinux/CentOS
  10), `dnf5` (Fedora 41+), `zypp-history`, `macos-install`, `restic`.

### Fixed
- `--last` read timestamps without a UTC offset (RFC 3164 syslog, most app
  logs) as UTC. They are local time: in Sydney `--last 1h` kept three hours
  of a local-time log, and anywhere west of UTC it kept nothing.
- `uv tool install logcrux` failed on every host without a system Python
  <= 3.14 (stock containers, RHEL 9, SLES 15, Ubuntu 22.04): uv picks the
  newest Python (3.15) and onnxruntime has no wheel for it. onnxruntime is
  now skipped on 3.15+ and logcrux runs without it (detection unchanged,
  incident naming less precise, said once on stderr); the docs pin
  `--python 3.12` for the full tool.
- haproxy: the container image's documented `log stdout format raw` output
  and its `[WARNING] (pid) :` stderr lines parse (were generic, CLEAN).
- RabbitMQ 3.9+ lines with a UTC offset parse (0/202 lines before).
- MongoDB 7 "Failed to authenticate" and PostgreSQL's own "password
  authentication failed for user" count toward brute force (a Postgres
  attack was a generic burst, named only when the classifier agreed).
- Non-root use (real VMs): `journalctl | logcrux` by a user who cannot read
  the system journal analysed journalctl's 4-line permission notice and
  reported CLEAN — it now says the input is that notice and how to get the
  real journal. An unreadable file says to use sudo instead of Click's
  "Invalid value for '[PATH]...'"; a directory run lists unreadable files
  once ("8 file(s) not readable by this user were skipped ... sudo") and
  shows members under the directory named, not a symlink's target.
- gunicorn's "Worker ... was sent SIGKILL! Perhaps out of memory?" (after a
  WORKER TIMEOUT) was a CRITICAL "Out of Memory"; the timeout is now a
  crash naming the worker, with timeout-specific remediation.
- Healthy boots on real VMs no longer raise boot-noise "error bursts": the
  boot phase ends at PID 1's "Startup finished", not a user session's
  (Alma 8), and Debian 13's per-reload systemd-ssh-generator / AF_VSOCK
  failure on VMs without vsock is known-benign.
- Binary files (wtmp, journal files, images) are refused with a hint
  (`journalctl --file`, `last -f`) instead of "analysed" into a CLEAN.
- A log NUL-padded by a crash was sniffed as UTF-16 and decoded to garbage
  (a real brute force reported CLEAN); NUL padding is now stripped.
- Non-UTF-8 bytes on stdin no longer abort the run.
- `journalctl` exports no longer fall to the generic parser: a low-coverage
  detection is re-detected across the whole file instead of being dropped to
  generic, `-o short-iso` kernel output parses, and indented continuation
  lines fold into their record. Routine boot-time noise is not an incident.
- PostgreSQL: a backend killed by a signal and the crash recovery it forces
  are reported (logged at LOG level, previously invisible); PG 13/14's
  "could not extend file" is disk full; SUSE's packaged log prefix parses.
- macOS `install.log`: a healthy Mac's 258-day log reported 67 "error
  bursts" (6,956 keyword errors, zero failed installs). Only installer
  failure wording is an error now; it is CLEAN. Program names with spaces and
  the RFC 3164 lines mixed into the file parse (87% -> 100% of lines).
- `journalctl -o short-precise` (microsecond timestamps) parses as syslog
  (generic on all six phase-3 VMs).
- `dnf.log` is no longer routed to the yum parser (0% coverage on RHEL 10).
- `zypp/history` on SLES no longer falls back because of `#` annotation lines.
- OpenSSH 9.8+ `penalty: failed authentication` lines count toward brute force.

### Changed
- Added a NOTICE file (Apache-2.0 §4(d)): redistributions carry the
  project's attribution. The license is unchanged.
- A no-baseline error burst must stand out from the log's own error rate when
  the log spans many windows: a 13-hour app log with a steady 1% error rate
  was reported as an "Error burst" (also in 0.9.0); a real 10-minute incident
  in the same log is still found.
- A generic "error burst" that is just the lines of a specific finding (an
  auth attack, an OOM) is folded into it instead of listed above it, and
  remediation follows the named incident, not the generic burst.
- Peak memory roughly halved on large logs (1.5 GB -> 0.7 GB for a 43 MB file).
- Install docs: verified platform table; `uv tool install` first, since stock
  cloud images ship no pip and several have Python older than 3.11.

## [0.9.0] - 2026-07-23

Initial public release.

- 209 log format parsers with automatic format detection, spanning Linux/Unix
  system logs, web servers, databases, containers, cloud infrastructure, and
  security tooling.
- Statistical anomaly detection: error rate spikes, burst detection, auth
  failure clustering, proxy/firewall anomalies, signal correlation.
- Local AI incident classification into 7 categories (OOM, auth brute-force,
  HTTP overload, disk full, service crash, config error, network issue) via
  bundled INT8-quantized ONNX models — no cloud, no telemetry, no API calls.
- Baseline tracking via local SQLite state.
- Rich terminal output and `--json` output for scripting.
- `--last` temporal filtering, `--format` overrides with common aliases,
  shell completion.
