# JSON output (schema version 2)

`logcrux --json` prints one object per analysed input; with several files or a
directory it prints a JSON **list** of them. Every key of the 0.9 output keeps
its meaning; version 2 (logcrux 0.10) only adds keys. Check `schema_version`
before relying on a key.

A real example — an SSH brute force on Rocky Linux 9 (`/var/log/secure`,
evidence trimmed to one line):

```json
{
  "schema_version": "2",
  "analysis_id": "6d8662f2-1342-423c-a9ba-e98f3b74b4e4",
  "level": "WARNING",
  "title": "Auth Brute Force",
  "findings": [
    {
      "headline": "Authentication failure cluster",
      "detail": "80 events",
      "kind": "auth_failure_cluster",
      "count": 80,
      "first_seen": "2026-10-13T10:03:19",
      "last_seen": "2026-10-13T10:04:50",
      "subjects": [
        {
          "label": "source",
          "value": "127.0.0.1",
          "count": 74
        },
        {
          "label": "user",
          "value": "root",
          "count": 8
        },
        {
          "label": "user",
          "value": "admin",
          "count": 8
        },
        {
          "label": "user",
          "value": "oracle",
          "count": 4
        }
      ],
      "evidence": [
        {
          "line": 98,
          "timestamp": "2026-10-13T10:03:22",
          "source": "sshd-session",
          "text": "Oct 13 10:03:22 lc-rocky-9-arm64 sshd-session[14411]: Invalid user admin from 127.0.0.1 port 42412",
          "message": "Invalid user admin from 127.0.0.1 port 42412"
        }
      ]
    }
  ],
  "confidence": 0.9587974548339844,
  "category": "auth_brute_force",
  "remediation": "Block offending IPs with `firewall-cmd --add-rich-rule` or fail2ban. Review /var/log/secure for source IPs and consider disabling password auth in sshd_config.",
  "log_path": "/var/log/secure",
  "parser_format": "syslog",
  "analyzed_at": "2026-10-19T20:17:58.971326Z",
  "parsed_count": 223,
  "skipped_count": 0,
  "elapsed_seconds": 0.15613912499975413,
  "time_range": {
    "start": "2026-10-13T08:45:48",
    "end": "2026-10-13T10:04:53",
    "duration_seconds": 4745.0
  },
  "severity_counts": {
    "info": 162,
    "error": 61
  },
  "coverage": {
    "lines": 223,
    "parsed": 223,
    "unparsed": 0,
    "ratio": 1.0
  },
  "warnings": [],
  "signal_count": 1,
  "last_error": null
}
```

## Top level

| key | meaning |
|---|---|
| `schema_version` | `"2"` |
| `level` | `CLEAN`, `INFO`, `WARNING` or `CRITICAL` (exit code 0 / 3 / 3 / 4) |
| `title` | the incident's name (the category's, or the lead finding's) |
| `category` | one of `oom`, `auth_brute_force`, `http_overload`, `disk_full`, `service_crash`, `config_error`, `network_issue`, `unknown` |
| `confidence` | 0-1; 1.0 on CLEAN, 0.9+ for deterministic signals, the classifier's otherwise |
| `findings` | up to five, most important first (below) |
| `signal_count` | every signal raised (`findings` lists at most five) |
| `remediation` | advice for the lead finding, or `null` |
| `log_path`, `parser_format` | the input and the format it was read as. A mixed stream reports `<primary>+<other>[+generic]`, e.g. `nginx-error+nginx-access` for `docker logs` of the nginx image |
| `parsed_count`, `skipped_count` | events analysed, non-blank lines no parser kept |
| `coverage` | `lines`, `parsed`, `unparsed`, `ratio` — what share of the input was understood |
| `time_range` | `start`, `end`, `duration_seconds` of the events' timestamps, or `null` |
| `severity_counts` | events per severity |
| `warnings` | sentences about the *input*: empty, journalctl's permission notice instead of the journal, no format recognised, `--last` kept nothing |
| `last_error` | on a CLEAN result for a short log: the error it ends on (an evidence line), the likely reason a container or job stopped — shown, not alarmed on |
| `analysis_id`, `analyzed_at`, `elapsed_seconds` | bookkeeping |

## A finding

| key | meaning |
|---|---|
| `kind` | the detector: `auth_failure_cluster`, `oom_event`, `service_crash`, `uncaught_exception`, `fatal_exit`, `backend_down`, `disk_full`, `storage_fault`, `policy_denial`, `config_error`, `job_failure`, `resource_limit`, `tls_error`, `clock_jump`, `mail_reject_cluster`, `error_burst`, `rate_spike`, `proxy_denial_cluster`, `tunnel_anomaly`, `firewall_block_cluster` |
| `headline`, `detail` | the human sentence; `detail` quotes the decisive line for single-line kinds (a job's `Fatal:`, the exception that killed a process, the server that went DOWN) |
| `count` | events behind the finding |
| `first_seen`, `last_seen` | its time span, or `null` without timestamps |
| `subjects` | what it is about, with counts over **every** matched event: `source` (IP) and `user` for auth; `killed` and `cgroup` for OOM; `unit`, `process`, `pod`, `service` for crashes; `status`, `path`, `client` for HTTP; `server`/`backend`; `image`, `pod`, `directive` for config errors; `limit` for resource limits; `offset` for clock jumps; `client` and `reason` for mail rejects; `script` for PHP fatals; otherwise `message` — the recurring message template with numbers, IPs and ids masked |
| `evidence` | up to three lines, one per message template, most frequent first, in file order: `line` (1-based, in the input as given), `timestamp`, `source`, `text` (verbatim, grep for it), `message` (without the timestamp/host prefix) |

Line numbers count the input's lines after decompression (`.gz`/`.bz2`); a
transport prefix logcrux strips (`docker logs --timestamps`, ANSI colour,
syslog `<PRI>`) does not shift them.
