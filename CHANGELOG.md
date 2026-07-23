# Changelog

All notable changes to logcrux are documented in this file.

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
