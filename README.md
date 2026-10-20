# logcrux

[![CI](https://github.com/ravipatip/logcrux/actions/workflows/ci.yml/badge.svg)](https://github.com/ravipatip/logcrux/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/logcrux)](https://pypi.org/project/logcrux/)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Coverage](https://img.shields.io/badge/coverage-91%25-brightgreen)
![Parsers](https://img.shields.io/badge/log%20formats-200%2B-blue)

> Licensed under the [Apache License 2.0](LICENSE). Copyright © 2026 Ravipati.
> Redistributions must keep the attribution in [NOTICE](NOTICE).

📖 **Full documentation: [logcrux.com](https://logcrux.com)**

**logcrux** is an intelligent, fully local log analyzer. Point it at a log
file and it tells you what's actually wrong: error bursts, brute-force
attacks, resource exhaustion, service failures, and more, using statistical
analysis plus a small local inference step for classification. Nothing
leaves your machine: no cloud, no telemetry, no API calls, no accounts.

Works on any text log, and natively covers 200+ formats: Linux/Unix
system logs plus web servers, databases,
containers, cloud infrastructure, and security tooling, most of which are
the same regardless of what OS is running logcrux itself.

---

## Test Results at a Glance

**Verdicts on real failures** — the number that matters. Faults were induced
on real systems (54 cloud VMs across 4 campaigns: Debian, Ubuntu, RHEL,
Rocky, AlmaLinux, CentOS Stream, SLES, openSUSE, x86_64 and arm64; plus
`docker logs` of 32 common images and a real Kubernetes cluster), each
capture labelled with what an operator should have been told *before*
logcrux saw it:

| 1,941 labelled real captures | logcrux 0.10.0 |
|---|---|
| faults detected (WARNING/CRITICAL) | **1563 / 1582 (99%)** |
| false alarms on healthy captures | **0 / 359** |
| incident category right, when it alarmed | 959 / 960 |
| log format recognised | 1721 / 1727 |

Read that as a development-set number: these captures drove the fixes. The
honest estimate for software logcrux has never seen is the **held-out
rounds**, each scored before any fix it prompted: **42 of 77 faults (55%)
on first contact**, 76 of 77 after, with no false alarms on the healthy
captures. Rounds: web/db/cache/queue images 13/18, proxies and app servers
4/4, Kubernetes 4/6, Tomcat/Kafka/kopia 3/7, PHP-FPM/Keycloak/OpenLDAP 0/3,
Prometheus/CoreDNS/Mosquitto/Envoy 2/4, resource limits/TLS/borg/Postfix
1/7, structured JSON apps 3/3, OS-level incidents on real VMs 8/13,
capacity limits 3/4, BIND/Samba 0/2, Go/Rust panics 1/2, Kubernetes
scheduling and probes 0/4. The misses are almost always a single
failure line in a vocabulary logcrux does not know yet; a
[wrong-verdict report](https://github.com/ravipatip/logcrux/issues/new?template=wrong-verdict.yml)
with the redacted lines is the fastest way to get one fixed.

On the 12-OS VM campaign of 2026-10-20 logcrux 0.9.0 detected **67%** of
the same faults; most misses were single-line failures — a crashed backend,
a failed backup, an SELinux denial — that a burst detector cannot see. The
captures, labels and scorer live in the project's lab repository and are
re-run against every release candidate.

Unit and integration tests, actual output of `pytest --cov=logcrux`:

```
$ pytest -q --cov=logcrux
...
TOTAL                                 11476   1025    91%
Required test coverage of 80% reached. Total coverage: 91.07%
1267 passed
```

See [docs/06-supported-log-types.md](docs/06-supported-log-types.md) for the full breakdown by category and a complete alphabetical index of every parser (the canonical count lives there).

---

## Features

- **Findings with evidence**: every incident names what it is about (the
  attacking IPs and users, the process the OOM killer chose, the crashed unit
  or pod, the 5xx status and path, the exception that killed a process) and
  cites the log lines, by number, that prove it
- **Single-line failures**: a failed backup job (restic, kopia, borg), a
  backend crash, an uncaught exception or fatal exit, a proxy with no live
  backend, an SELinux/AppArmor denial, a degraded RAID array, a rejected
  config, an expired certificate, an exhausted file-descriptor or process
  limit, a jumped clock, a held package-manager lock — not only bursts
- **200+ log format parsers** with automatic format detection; `docker logs`
  streams that interleave formats are parsed line by line; a generic fallback
  so any text log still analyzes
- **Files, directories, stdin**: `logcrux /var/log/nginx/`, rotated `.gz`,
  `journalctl`/`kubectl logs`/`docker logs` piped in
- **Local classification**: 7 incident categories (OOM, auth brute-force,
  HTTP overload, disk full, service crash, config error, network issue)
- **Fully local**: no cloud, no telemetry, no external API calls
- **JSON output** with a versioned schema for scripts, CI gates (`--fail-on`)
  and agents
- **Temporal filtering** via `--last 1h`, `--last 30m`, etc.
- **Baseline tracking**: compares current runs against historical norms (SQLite)

---

## Installation

```bash
# Recommended: isolated install, no venv to manage
uv tool install --python 3.12 logcrux     # or one-off: uvx --python 3.12 logcrux ...
pipx install logcrux

# Into an existing environment
pip install logcrux
uv pip install logcrux

# Development install
git clone https://github.com/ravipatip/logcrux
cd logcrux
pip install -e ".[dev]"
```

Requires **Python 3.11+** and, for the full tool, **glibc ≥2.28** (Alpine/musl
runs without the AI naming step, see below).

**Why `--python 3.12`:** with no compatible system Python, uv installs the
newest one (3.15 as of October 2026), and onnxruntime — which runs the small
classification models — has no wheel for it yet. logcrux still installs and
detects incidents without it, but names them less precisely (on the
1,191-capture scorecard: detection unchanged, incident category right 77% of
the time instead of 100%) and says so on stderr ("AI classification
unavailable"). Pinning 3.11–3.14 gets the full tool. `uv` downloads a matching interpreter automatically if your
system doesn't have one, handy on distros whose default system Python is
older (RHEL/Rocky 9, Ubuntu 22.04, Amazon Linux 2023 and SLES 15 ship
3.6-3.10 by default). `pipx` uses whatever Python is already on your `PATH`, so install
3.11+ first if needed (`sudo dnf install python3.11` / `sudo apt install
python3.11`). Inference models are embedded, no separate download needed.
`uv`/`uvx` work out of the box since logcrux ships a standard
`[project.scripts]` entry point; no special packaging is needed for either.

### Supported platforms

Both `x86_64` and `arm64` are supported, on Linux and macOS. The rows marked
**verified** were installed and run on real cloud VMs (2026-10-13): `uv tool
install` worked on every one of them, x86_64 and arm64. A stock cloud image
ships **no pip at all**, and several ship a system Python older than 3.11 —
which is why `uv` (it fetches its own interpreter) is the recommended route.

| OS | system Python | uv | pip into a venv | |
|---|---|---|---|---|
| Ubuntu 24.04 (x86_64, arm64) | 3.12 | yes | yes | verified |
| Ubuntu 22.04 | **3.10** | yes | install 3.11 first | verified |
| Debian 13 | 3.13 | yes | yes | verified |
| Debian 12 | 3.11 | yes | yes | verified |
| RHEL 10 / AlmaLinux 10 / CentOS Stream 10 | 3.12 | yes | yes | verified |
| RHEL 9 / Rocky Linux 9 | **3.9** | yes | install 3.11 first | verified |
| SLES 15 SP7 | **3.6** | yes | install 3.11 first | verified |
| openSUSE Leap 16 | 3.13 | yes | yes | verified |
| Rocky/AlmaLinux 8, Amazon Linux 2023 | 3.6–3.9 | yes | install 3.11 first | |
| Fedora | current | yes | yes | |
| Alpine | – | yes, without AI naming | no | no musl onnxruntime wheel: plain `uv tool install logcrux` runs degraded (verified in a container, 2026-10-20) |
| macOS | – | yes | yes | Apple Silicon and Intel |

The blocker on older enterprise distros is glibc, not Python: onnxruntime
only ships modern `manylinux_2_27`/`manylinux_2_28` wheels, and below glibc
2.28 the `uv` installer silently falls back to a musl build, which then
can't find a matching onnxruntime wheel either. RHEL/Rocky/AlmaLinux 8+,
Ubuntu 20.04+, Debian 10+, Amazon Linux 2023, any current Fedora, and
openSUSE Leap 15.3+/SLES 15 SP3+ all clear the glibc 2.28 floor.
RHEL/CentOS 7, Amazon Linux 2, Ubuntu 18.04 and older, and SLES 12 do not;
run logcrux from outside those hosts instead (`ssh oldbox 'cat
/var/log/secure' | logcrux`, or a sidecar container on a glibc 2.28+ base).

On Alpine/musl onnxruntime publishes no wheel, so only the degraded mode
is available (plain `uv tool install logcrux`, which picks a Python without
onnxruntime): detection works, incident naming is less precise. For the full
tool use a glibc base image, or `docker logs <container> | logcrux` from
outside it.

See [docs/21-troubleshooting.md](docs/21-troubleshooting.md) for
distro-specific fixes (PEP 668 `externally-managed-environment`, `uv`
PATH/tar issues, RHEL-family Python upgrades, etc).

---

## Quick Start

```bash
# A file, several files, or a whole directory (one level; binaries skipped)
logcrux /var/log/secure
logcrux /var/log/nginx/
logcrux /var/log/syslog /var/log/auth.log

# What a container or pod said before it died
docker logs myapp 2>&1 | logcrux
docker logs --timestamps myapp 2>&1 | logcrux
docker compose logs --no-color | logcrux
kubectl logs deploy/api --previous | logcrux
kubectl get events -A | logcrux

# The systemd journal (as root, or in the systemd-journal group)
journalctl -b | logcrux
journalctl -u nginx --since "1 hour ago" | logcrux

# Rotated and compressed logs are read directly
logcrux /var/log/syslog.2.gz

# Only the last hour of a long log
logcrux /var/log/nginx/access.log --last 1h

# JSON for scripts, CI gates and agents (a list when several files are given)
logcrux /var/log/syslog --json

# Every evidence line, full width, plus debug detail on stderr
logcrux /var/log/syslog --verbose

# Check the install itself (Python, models, state DB) — paste this in bug reports
logcrux --doctor
```

stdin is read to the end before analysis, so pipe a bounded slice
(`journalctl -b`, `tail -n 20000 file`), not a stream that never ends
(`tail -f`).

What you get — a real SSH brute force on Rocky Linux 9 (`/var/log/secure`):

```
╭───────────────────────   WARNING    Auth Brute Force ────────────────────────╮
│ ● Authentication failure cluster  (80 events)                                │
│     2026-10-13 10:03:19 → 10:04:50 (1m31s)                                   │
│     source: 127.0.0.1 ×74 · user: root ×8, admin ×8, oracle ×4               │
│     line 98: sshd-session: Invalid user admin from 127.0.0.1 port 42412      │
│     line 100: sshd-session: pam_unix(sshd:auth): authentication failure; l…  │
│                                                                              │
│ Confidence: 96%                                                              │
│                                                                              │
│ Remediation: Block offending IPs with `firewall-cmd --add-rich-rule` or      │
│ fail2ban. Review /var/log/secure for source IPs and consider disabling       │
│ password auth in sshd_config.                                                │
╰──────────────────────────────────────────────────────────────────────────────╯
Checked 223 events as syslog  │  100% of 223 lines parsed  │  2026-10-13
08:45:48 → 10:04:53 (1h19m)  │  61 error · 0 warning
```

Every finding says what it is about (attacking IPs and users, the process
the OOM killer chose, the unit that crashed, the HTTP status and path of a
5xx flood, the exception that killed a process) and points at the lines, by
number, that prove it. A clean result says what was checked, so "CLEAN"
never just means "didn't work". `--json` carries the same evidence
(`findings[].subjects`, `findings[].evidence[].line`) plus `schema_version`;
every key is described in [docs/23-json-output.md](docs/23-json-output.md).

**Exit codes:** `0` = clean, `3` = info/warning found, `4` = critical incident
found (with several files, the worst of them), `1` = bad option or config,
`2` = unreadable, missing or binary input. In CI, `--fail-on critical` exits
non-zero only for CRITICAL, and `--fail-on never` always exits 0 on a
completed analysis.

### How you invoke it

The examples above assume `logcrux` is on your `PATH`. Whether it is
depends on how you installed it:

| installed with | invoke as |
|---|---|
| `uv tool install --python 3.12` or `pipx` | `logcrux ...`, already on `PATH` |
| `pip` into a venv | `~/.venvs/logcrux/bin/logcrux ...`, or activate the venv first |
| no install, one-off run | `uvx --python 3.12 logcrux ...` |

Everything else (flags, stdin, exit codes) is identical regardless of
which form you use; substitute your invocation for the literal
`logcrux`.

### Shell completion

Enable tab-completion for your shell (bash, zsh, fish, PowerShell):

```bash
logcrux --install-completion       # install for the current shell
logcrux --show-completion          # print the script to inspect/customize
```

### Permissions

logcrux is an on-demand CLI, not a daemon or agent: installing it via `pip`
does **not** create a `logcrux` system user or group, open a port, or run
anything in the background. It runs with **the caller's privileges and reads
only what the caller can read**, for the duration of one analysis, then exits.

That matters on locked-down hosts (e.g. a fresh RHEL EC2 box), where the
interesting logs are root-only: `/var/log/secure` is `root:root` mode `0600`,
and `/var/log/messages` is typically unreadable to normal users. A plain
`logcrux /var/log/secure` will simply get permission-denied: logcrux has no
special powers. To analyze them, pick whichever fits your setup:

```bash
# 1. Run as root for ad-hoc analysis
sudo logcrux /var/log/secure

# 2. Least-privilege for the journal: join systemd-journal, pipe journalctl
#    (logcrux parses `journalctl -o short-iso` from stdin)
sudo usermod -aG systemd-journal "$USER"     # then re-login
journalctl -o short-iso | logcrux

# 3. Grant a read-only user access to specific files via ACLs
sudo setfacl -m u:loguser:r /var/log/secure
```

---

## Supported Log Formats

logcrux auto-detects the log format from the file path and content. You can also override with `--format <name>`.

**200+ formats.** Below are representative examples from each category. Use `logcrux --help` or check [docs/06-supported-log-types.md](docs/06-supported-log-types.md) for the complete list.

### System & Auth

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| Syslog | `syslog` | `/var/log/syslog`, `/var/log/messages` | Service errors, kernel events |
| Journald | `journald` | `journalctl` output | Systemd unit failures, boot issues |
| Auth / Secure | `secure` | `/var/log/auth.log`, `/var/log/secure` | SSH brute force, sudo, PAM auth failures |
| UFW / iptables | `ufw` | `/var/log/ufw.log` | Firewall BLOCK events, port scan patterns |
| fail2ban | `fail2ban` | `/var/log/fail2ban.log` | Ban storms, jail activity, active attack signals |
| macOS unified log | `macos-unified` | `log show` output (default, compact, syslog styles) | Faults by subsystem, using macOS's own levels |

### Web Servers & Proxies

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| Nginx Access | `nginx-access` | `/var/log/nginx/access.log` | HTTP error rate spikes, traffic anomalies |
| Nginx Error | `nginx-error` | `/var/log/nginx/error.log` | Upstream failures, connection errors |
| Apache Access | `apache-access` | `/var/log/httpd/access_log` | 5xx spikes, traffic anomalies |
| Apache Error | `apache-error` | `/var/log/httpd/error_log` | PHP errors, config issues |
| HAProxy | `haproxy` | `/var/log/haproxy.log` | Backend down, 5xx errors, TCP termination faults |
| Squid | `squid` | `/var/log/squid/access.log` | Denied requests, proxy anomalies |

### Databases

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| MySQL / MariaDB | `mysql` | `/var/log/mysql/error.log` | Auth failures, slow queries (≥5 s), crashes, disk full |
| PostgreSQL | `postgresql` | `/var/log/postgresql/*.log` | FATAL/PANIC, auth failures, deadlocks, disk full |
| Redis | `redis` | `/var/log/redis/redis-server.log` | OOM evictions, fork failures, replication issues, crashes |

### Containers & Orchestration

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| Docker | `docker` | `/var/lib/docker/containers/*/*.log` | Container crashes, OOM kills, panic traces |
| Kubernetes | `kubernetes` | `/var/log/pods/**/*.log` | OOMKilled pods, CrashLoopBackOff, evictions |

### Mail & FTP

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| Postfix | `postfix` | `/var/log/mail.log`, `/var/log/maillog` | SASL auth failures, bounces, relay rejects |
| FTP (vsftpd / xferlog) | `ftp` | `/var/log/vsftpd.log`, `/var/log/xferlog` | Failed logins, interrupted transfers |

### Infrastructure, Network, DNS & HA

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| OpenLDAP | `slapd` | `/var/log/slapd.log` | Bind/auth failures (`err=49`), search limits, connection drops |
| NetworkManager | `networkmanager` | `/var/log/syslog` (tagged) | Activation failures, DHCP timeouts, carrier/link loss |
| firewalld | `firewalld` | `/var/log/firewalld` | `COMMAND_FAILED`, rule errors, zone warnings |
| keepalived | `keepalived` | `/var/log/syslog` (tagged) | VRRP state transitions, FAULT state, healthcheck failures |
| strongSwan / IPsec | `strongswan` | `/var/log/syslog` (tagged) | IKE_SA failures, retransmits, no-proposal, auth failures |
| smartd (S.M.A.R.T.) | `smartd` | `/var/log/syslog` (tagged) | Failing disks, pending/uncorrectable sectors, ATA errors |
| CoreDNS | `coredns` | container / file logs | SERVFAIL, i/o timeouts, plugin errors |
| HashiCorp (Consul/Vault/Nomad) | `hashicorp` | `/var/log/{consul,vault,nomad}` | No cluster leader, unseal failures, election churn |

### App Servers, Queues & Service Managers

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| etcd | `etcd` | container / file logs (zap JSON) | Slow applies, deadline exceeded, peer inactivity |
| ZooKeeper | `zookeeper` | `/var/log/zookeeper/*.log` | Leader-follower exceptions, fatal exits |
| Traefik | `traefik` | container / file logs (JSON) | Backend errors, upstream refused, config errors |
| Caddy | `caddy` | container / file logs (JSON) | 5xx access logs, no upstreams, cert failures |
| supervisord | `supervisor` | `/var/log/supervisor/supervisord.log` | FATAL state, `gave up`, crash loops |
| Celery | `celery` | worker logs | Task failures, WorkerLostError, broker disconnects |
| CUPS | `cups` | `/var/log/cups/error_log` | Print scheduler errors, listen-socket failures |

### Cloud-Native & DevOps

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| CRI (containerd) | `cri` | `/var/log/containers/*.log`, `/var/log/pods/` | OOMKilled, CrashLoopBackOff |
| klog (Kubernetes components) | `klog` | kubelet/apiserver logs | Component panics, leader elections |
| klog JSON | `klog-json` | `--logging-format=json` k8s components | Structured k8s component errors |
| OTLP log records | `otlp` | OpenTelemetry pipelines | Error/fatal severity events |
| Envoy / Istio | `envoy` | Istio sidecar logs | Upstream errors, health check failures |
| AWS ALB / ELB | `alb` | ALB access logs | 5xx spikes, target errors |
| AWS VPC Flow | `vpcflow` | VPC flow log files | Rejected flows, traffic anomalies |
| Cloud-init | `cloud-init` | `/var/log/cloud-init.log` | Boot failures, provisioning errors |
| CloudWatch agent | `cloudwatch` | CloudWatch agent logs | Agent errors, delivery failures |
| Fluent Bit / Fluentd | `fluentbit` | Agent logs | Input/output plugin errors |
| AWS CloudTrail | `cloudtrail` | CloudTrail JSON | API auth failures, unusual API calls |
| GCP Cloud Logging | `gcp` | Cloud Logging JSON | Error log entries, severity spikes |
| GitLab | `gitlab` | `production_json.log` | 5xx errors, worker crashes |
| Terraform | `terraform` | `TF_LOG=json` output | Plan/apply errors |
| GitHub Actions | `githubactions` | Actions runner logs | Step failures, job errors |

### Security & SIEM

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| CEF | `cef` | ArcSight / SIEM exports | High-severity security events |
| LEEF | `leef` | IBM QRadar exports | Authentication/network alerts |
| Zeek / Bro | `zeek` | `/var/log/zeek/` (TSV) | Connection anomalies, DNS issues |
| Suricata (EVE JSON) | `suricata` | `/var/log/suricata/eve.json` | IDS alerts, anomalies |
| Wazuh / OSSEC | `wazuh` | Wazuh alert JSON | High rule-level security alerts |
| ModSecurity | `modsecurity` | WAF audit log | SQL injection, XSS, rule violations |
| Snort | `snort` | `/var/log/snort/alert` | IDS alerts |
| Cisco ASA / FTD | `ciscoasa` | Syslog from ASA | Denied connections, auth failures |
| Palo Alto PAN-OS | `paloalto` | PAN-OS CSV logs | Threat/traffic deny events |
| FortiGate | `fortigate` | FortiOS key=value logs | Threat/virus detections |
| pfSense / OPNsense | `pfsense` | filterlog lines | Blocked traffic patterns |
| Falco | `falco` | Falco JSON output | Runtime security rule violations |
| osquery | `osquery` | osqueryd results JSON | Suspicious process/file events |
| Okta System Log | `okta` | Okta JSON events | Failed logins, policy violations |
| AppArmor | `apparmor` | `/var/log/syslog` (kernel) | Denied operations |

### Identity & Access Management (Ping Identity)

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| PingFederate | `pingfederate` | `pingfederate/log/{server,admin,audit}.log` | SSO/OAuth failures, signature errors, startup failures, failed admin/audit events |
| PingAccess | `pingaccess` | `<PA_HOME>/log/pingaccess{,_engine_audit,_api_audit}.log` | Token validation failures, backend-connect errors, 4xx/5xx from the audit response code |
| PingDirectory | `pingdirectory` | `<PD>/logs/{errors,access}` | Failed LDAP binds (`resultCode=49`), `SEVERE_ERROR` events, disk-full |
| PingDirectoryProxy | `pingdirectoryproxy` → `pingdirectory` | `<PD>/logs/{errors,access}` | Same Ping Data platform format as PingDirectory |
| PingDataSync | `pingdatasync` → `pingdirectory` | `<PDS>/logs/sync` | Dropped/failed change syncs (`category=SYNC`), pipe failures |
| PingAuthorize / PingDataGovernance | `pingauthorize` (`pingdatagovernance`) | `<PAZ>/logs/policy-decision` | `DENY`/`INDETERMINATE` policy decisions (JSON) |
| PingIntelligence (ASE) | `pingintelligence` | `/opt/pingidentity/ase/logs/{access,controller,balancer}.log` | Attack/decoy hits, connection drops, backend-connect errors |

### Observability & Logging Agents

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| logfmt (Prometheus/Loki) | `logfmt` | Prometheus/Loki/Vector logs | Component errors |
| Logrus (structured) | `logrus` | containerd/dockerd/Calico logs | Error/fatal events |
| Pino (Node.js) | `pino` | Node.js JSON logs | Error severity events |
| Bunyan (Node.js) | `bunyan` | Node.js JSON logs | Error/fatal events |
| Winston (Node.js) | `winston` | Node.js JSON logs | Error events |
| Serilog (.NET CLEF) | `serilog` | .NET application logs | Error/fatal events |
| Logstash | `logstash` | `logstash.*` logger | Pipeline errors |
| Filebeat (ECS JSON) | `filebeat` | Beats JSON output | Error events |
| Datadog agent | `datadog` | Datadog agent logs | Agent errors |
| Telegraf | `telegraf` | Telegraf logs | Plugin errors |
| Kibana | `kibana` | Kibana log file | Error events |
| Zabbix | `zabbix` | Zabbix server log | Alert/error events |
| Nagios / Icinga | `nagios` | Nagios core log | Service/host alerts |

### Databases (Extended)

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| MongoDB | `mongodb` | `/var/log/mongodb/mongod.log` | Connection errors, replication lag |
| Elasticsearch | `elasticsearch` | `/var/log/elasticsearch/*.log` | Shard failures, GC pressure |
| Cassandra | `cassandra` | `/var/log/cassandra/system.log` | Timeouts, dropped messages |
| ClickHouse | `clickhouse` | ClickHouse server log | Query errors, OOM |
| MSSQL | `mssql` | SQL Server ERRORLOG | Error/warning events |
| Oracle | `oracle` | alert log | ORA- / TNS- errors |
| CockroachDB | `cockroachdb` | crdb-v2 log | Fatal/error events |
| pgBouncer | `pgbouncer` | pgBouncer log | Pool errors, auth failures |
| Neo4j | `neo4j` | `debug.log` | Error/fatal events |
| HBase / Hive / Flink / Druid | `hbase` / `hive` / `flink` / `druid` | Log4j logs | JVM errors, task failures |
| Trino / Presto | `trino` | airlift log | Query/worker errors |
| Spark | `spark` | driver/executor log | Job failures, OOM |
| Hadoop (HDFS/YARN) | `hadoop` | HDFS/YARN log4j | Service errors |

### Mail (Extended)

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| Dovecot | `dovecot` | `/var/log/dovecot*` | Auth failures, quota errors |
| Exim | `exim` | `/var/log/exim4/` | Bounce/rejection patterns |
| Sendmail | `sendmail` | `/var/log/maillog` | Auth failures, bounces |
| OpenSMTPD | `opensmtpd` | smtpd logs | Auth/delivery failures |
| rspamd | `rspamd` | rspamd log | High-score spam, errors |
| SpamAssassin | `spamassassin` | spamd log | High-score results |
| OpenDKIM | `opendkim` | syslog-tagged | DKIM verification failures |

### Storage, Virtualization & Linux Daemons

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| Ceph | `ceph` | Ceph OSD/MON logs | OSD errors, full warnings |
| ZFS (zed) | `zfs` | zed event logs | Pool errors, checksum failures |
| mdadm (RAID) | `mdadm` | syslog-tagged | Array degraded, member failed |
| GlusterFS | `glusterfs` | GlusterFS log | Brick failures, split-brain |
| libvirt | `libvirt` | libvirtd log | VM errors, storage issues |
| Podman | `podman` | Podman event log | Container errors, OOM |
| QEMU / KVM | `qemu` | QEMU log | VM crashes, I/O errors |
| VMware ESXi | `vmware` | ESXi log | VM errors, storage issues |
| AppArmor | `apparmor` | syslog kernel lines | Denied operations |
| rsyslog / syslog-ng | `rsyslog` / `syslogng` | daemon logs | Forwarding errors |
| D-Bus / polkit | `dbus` / `polkit` | syslog-tagged | Auth denials |

### Backup & Data Protection

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| restic | `restic` | `restic backup` / `check` output, text or `--json` | Failed jobs (wrong password, missing source, repository gone), partial snapshots |
| kopia | `kopia` | `kopia snapshot create` / `repository connect` output | Failed snapshots and connections, with kopia's reason |
| BorgBackup | `borg` | `borg create --stats` output | Wrong passphrase, missing repository, lock failures, unreadable sources |

### Application Frameworks

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| Any JSON-lines app log | `json` | One JSON object per line with a level and a message field (Python structlog, Go zap / slog / zerolog, logrus / loguru JSON) | Errors, error bursts, a fatal record as the process's last line |
| Spring Boot (Logback) | `springboot` | Spring app logs | ERROR/FATAL events |
| Log4j / JBoss | `log4j` | Java app logs | Error/fatal events |
| Jetty | `jetty` | Jetty StdErr log | Server errors |
| WildFly / JBoss | `wildfly` | WildFly server log | Deployment/server errors |
| PHP error log | `phperror` | `/var/log/php_errors.log` | Fatal/parse errors |
| Laravel / Monolog | `laravel` | `storage/logs/laravel.log` | Error/critical events |
| Django (runserver) | `django` | Django dev log | 500 errors, exceptions |
| Rails | `rails` | Rails request log | 500 errors, exceptions |
| uvicorn / Gunicorn | `uvicorn` / `gunicorn` | ASGI/WSGI worker logs | Worker crashes, timeouts |
| Go stdlib log | `gostdlib` | Go app logs | Error-prefix messages |
| Elixir / Phoenix | `phoenix` | Phoenix log | Error events |
| Airflow | `airflow` | Airflow task logs | Task failures, scheduler errors |
| Sidekiq | `sidekiq` | Sidekiq worker log | Job failures, worker errors |
| Ansible | `ansible` | Playbook output | Task failures |
| Jenkins | `jenkins` | `jenkins.log` | Build failures, exceptions |

### Network & Infrastructure (Extended)

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| Pi-hole FTL | `pihole` | `/var/log/pihole-FTL.log` | DNS errors, gravity failures |
| FRR / Quagga | `frr` | routing daemon logs | BGP/OSPF peering issues |
| MikroTik RouterOS | `mikrotik` | RouterOS syslog | Critical/error events |
| UniFi | `unifi` | UniFi controller log | Device errors, auth failures |
| OpenVPN | `openvpn` | `/var/log/openvpn*` | Auth failures, tunnel drops |
| WireGuard | `wireguard` | wireguard-go log | Peer handshake failures |
| Tailscale | `tailscale` | tailscaled log | Connectivity errors |
| BIND9 (named) | `named` | `/var/log/named*` | Resolution failures, DNSSEC errors |
| PowerDNS | `powerdns` | pdns_server log | Backend errors, timeouts |
| Unbound | `unbound` | Unbound DNS log | Resolution failures |
| dnsmasq | `dnsmasq` | syslog-tagged | DHCP/DNS errors |
| Kong (API gateway) | `kong` | Kong JSON log | Upstream errors, latency spikes |
| Cloudflare Logpush | `cloudflare` | Cloudflare JSON | High error-rate events |
| AWS S3 access | `s3access` | S3 REST access log | Error responses |
| AWS CloudFront | `cloudfront` | CloudFront W3C log | Error status codes |
| IIS | `iis` | IIS W3C log | 5xx errors |

### Package Management, Build & CI

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| dpkg / apt history | `dpkg` / `apthistory` | Debian package logs | Installation errors |
| dnf (RHEL / Rocky / Alma / CentOS 8-10) | `dnf` | `/var/log/dnf.log` | Failed transactions and commands |
| dnf5 (Fedora 41+) | `dnf5` | `/var/log/dnf5.log` | Failed transactions |
| yum (EL7 and older) | `yum` | `/var/log/yum.log` | Transaction errors |
| zypper history (SLES / openSUSE) | `zypp-history` | `/var/log/zypp/history` | Install and remove history |
| macOS installer | `macos-install` | `/var/log/install.log` | Failed installs |
| pip | `pip` | pip install output | Installation failures |
| npm | `npm` | npm log | Error events |
| Maven | `maven` | Maven build output | Build failures |
| Gradle | `gradle` | Gradle build output | Build failures |
| Bazel | `bazel` | Bazel output | Build errors |
| Certbot | `certbot` | Certbot log | Renewal failures |

### Fallback

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
| Generic | `generic` | Any plain-text log | Timestamps, severity keywords (best-effort) |

---

## Incident Categories

The AI classifier maps detected signals to one of seven categories:

| Category | Triggered by |
|----------|-------------|
| `auth_brute_force` | SSH failures, SASL failures, FTP FAIL LOGINs, UFW blocks on port 22, fail2ban bans |
| `service_crash` | HAProxy backend down, MySQL/PG FATAL/PANIC, Docker panics, k8s CrashLoopBackOff |
| `oom` | Docker/k8s OOMKilled, Redis `Cannot allocate memory`, kernel OOM killer |
| `http_overload` | HAProxy 5xx, Nginx/Apache upstream errors, 503/502 spikes |
| `disk_full` | MySQL/PG `No space left on device`, Redis RDB/AOF write errors |
| `network_issue` | HAProxy/Postfix timeouts, Redis replication lag, k8s CNI failures |
| `config_error` | MySQL unknown variable, PG invalid parameter, Redis CONFIG errors |

---

## Configuration

Config files are loaded from (in order):
1. `--config <path>` CLI flag
2. `~/.config/logcrux/logcrux.yaml`
3. `/etc/logcrux/logcrux.yaml`

```yaml
analysis:
  window_size_minutes: 5        # Time window for burst/rate analysis
  burst_multiplier: 3.0          # Burst threshold = baseline × multiplier
  auth_failure_threshold: 10     # Events to trigger auth_failure_cluster signal
  spike_factor: 3.0              # Error rate spike threshold
  correlation_gap_seconds: 120   # Max gap between correlated signals

inference:
  enabled: true                  # Enable AI classification
  threshold: 0.35                # Min confidence to report a finding (softmax threshold)

state:
  db_path: ~/.local/share/logcrux/state.db
  baseline_alpha: 0.2            # Exponential smoothing for baseline updates

security:
  allowed_log_paths:
    - /var/log/
    - /tmp/
  max_file_size_mb: 2048

output:
  color: true
  show_remediation: true
```

---

## Architecture

```
Log file / stdin
     │
     ▼
┌─────────────┐    Auto-detect format
│   Parsers   │  ──────────────────────▶  ParsedEvent[]
│ (200+ types)│
└─────────────┘
     │
     ▼
┌──────────────────┐
│ Statistical      │    error_rate · burst · anomaly · correlation
│ Analysis Engine  │  ──────────────────────────────────────────▶  AnomalySignal[]
└──────────────────┘
     │
     ▼
┌─────────────────┐
│ Local Inference │    groups related events, names the
│ (offline)       │    likely incident category                  InferenceResult
└─────────────────┘
     │
     ▼
┌─────────────────┐
│  Summarizer     │  ──────────────────────────────────────────▶  IncidentSummary
└─────────────────┘
     │
     ▼
  Rich terminal output  /  JSON
```

---

## Performance

Measured with logcrux 0.10.0 on an Apple M-series laptop (nginx access
logs; the real-VM campaign saw 38-65 s for 510 K lines on 2 vCPUs):

| input | time | peak memory |
|---|---|---|
| 1 line | 0.15 s | 54 MB |
| 100 K lines | 2.8 s | 179 MB |
| 500 K lines (with an incident to classify) | 13.8 s | 820 MB |
| same 500 K, `--last 1h` | — | 611 MB |
| `tail -n 100000 file \| logcrux` | — | 208 MB |

The whole input is held in memory while it is analysed (~1.3 KB per line,
plus ~250 MB for the classification models, loaded only when there is
something to classify). For multi-gigabyte logs, analyse a slice:
`tail -n 200000`, `journalctl --since "2 hours ago"`, or `grep` the service
first. `--last` filters after parsing, so it reduces memory less than
slicing the input does.

---

## Running Tests

```bash
# All tests with coverage report
pytest

# Parser tests only
pytest tests/unit/test_parsers/ -v

# Integration tests
pytest tests/integration/

# Specific parser
pytest tests/unit/test_parsers/test_haproxy.py -v
```

Current coverage: **89%** across all modules (1050 tests).

---

## License

logcrux is licensed under the [Apache License 2.0](LICENSE): free to use,
modify, and redistribute, including commercially, with attribution: keep the
[LICENSE](LICENSE) and the [NOTICE](NOTICE) file (Copyright 2026 Ravipati)
with any copy or derivative work.

---

📖 Docs: [logcrux.com](https://logcrux.com) · 🐛 Issues: [GitHub](https://github.com/ravipatip/logcrux/issues) · 📦 [PyPI](https://pypi.org/project/logcrux/)
