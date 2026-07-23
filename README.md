# logcrux

[![CI](https://github.com/ravipatip/logcrux/actions/workflows/ci.yml/badge.svg)](https://github.com/ravipatip/logcrux/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/logcrux)](https://pypi.org/project/logcrux/)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Coverage](https://img.shields.io/badge/coverage-89%25-brightgreen)
![Parsers](https://img.shields.io/badge/log%20formats-200%2B-blue)

> Licensed under the [Apache License 2.0](LICENSE). Copyright © 2026 Ravipati.

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

Actual output of `pytest --cov=logcrux` against this codebase (reproduce it yourself, nothing here is hand-typed):

```
$ pytest -q
...
TOTAL                                9748   1034    89%
Required test coverage of 80% reached. Total coverage: 89.39%
1050 passed in 3.16s
```

See [docs/06-supported-log-types.md](docs/06-supported-log-types.md) for the full breakdown by category and a complete alphabetical index of every parser (the canonical count lives there).

---

## Features

- **200+ log format parsers** with automatic format detection, plus a generic
  fallback so any text log still analyzes
- **AI-powered incident classification**: 7 incident categories (OOM, auth brute-force, HTTP overload, disk full, service crash, config error, network issue)
- **Statistical anomaly detection**: error rate spikes, burst detection, auth failure clustering
- **Fully local**: no cloud, no telemetry, no external API calls
- **Rich terminal output** with color-coded severity and remediation hints
- **JSON output** for scripting and pipeline integration
- **Temporal filtering** via `--last 1h`, `--last 30m`, etc.
- **Baseline tracking**: compares current runs against historical norms (SQLite)

---

## Installation

```bash
# Recommended: isolated install, no venv to manage
uv tool install logcrux        # or run without installing: uvx logcrux ...
pipx install logcrux

# Into an existing environment
pip install logcrux
uv pip install logcrux

# Development install
git clone https://github.com/ravipatip/logcrux
cd logcrux
pip install -e ".[dev]"
```

Requires **Python 3.11+** and **glibc ≥2.28** (Alpine/musl is not supported,
see below). `uv` downloads a matching interpreter automatically if your
system doesn't have one, handy on distros whose default system Python is
older (Amazon Linux 2023, RHEL 9, and Ubuntu 22.04 all ship 3.9-3.10 by
default). `pipx` uses whatever Python is already on your `PATH`, so install
3.11+ first if needed (`sudo dnf install python3.11` / `sudo apt install
python3.11`). Inference models are embedded, no separate download needed.
`uv`/`uvx` work out of the box since logcrux ships a standard
`[project.scripts]` entry point; no special packaging is needed for either.

### Supported platforms

Both `x86_64` and `arm64` are supported, on Linux and macOS:

| OS | uv | pip (venv) | notes |
|---|---|---|---|
| Ubuntu 20.04+ | yes | yes | 24.04 defaults to Python 3.12 |
| Debian 10+ | yes | yes | 12 defaults to Python 3.11 |
| Fedora | yes | yes | defaults to a current Python |
| Rocky Linux / AlmaLinux 8+ | yes | yes | default Python is 3.9, install 3.11 for pip |
| Amazon Linux 2023 | yes | yes | default Python is 3.9, install 3.11 for pip |
| openSUSE Leap 15.3+ | yes | yes | default Python is 3.6, install 3.11 for pip |
| Alpine | no | no | musl not supported, no onnxruntime wheel |
| macOS | yes | yes | Apple Silicon and Intel |

The blocker on older enterprise distros is glibc, not Python: onnxruntime
only ships modern `manylinux_2_27`/`manylinux_2_28` wheels, and below glibc
2.28 the `uv` installer silently falls back to a musl build, which then
can't find a matching onnxruntime wheel either. RHEL/Rocky/AlmaLinux 8+,
Ubuntu 20.04+, Debian 10+, Amazon Linux 2023, any current Fedora, and
openSUSE Leap 15.3+/SLES 15 SP3+ all clear the glibc 2.28 floor.
RHEL/CentOS 7, Amazon Linux 2, Ubuntu 18.04 and older, and SLES 12 do not;
run logcrux from outside those hosts instead (`ssh oldbox 'cat
/var/log/secure' | logcrux`, or a sidecar container on a glibc 2.28+ base).

Alpine/musl isn't supported at any Python version, since onnxruntime
publishes no `musllinux` wheels. Use a glibc base image, or
`docker logs <container> | logcrux` from outside it.

See [docs/21-troubleshooting.md](docs/21-troubleshooting.md) for
distro-specific fixes (PEP 668 `externally-managed-environment`, `uv`
PATH/tar issues, RHEL-family Python upgrades, etc).

---

## Quick Start

```bash
# Analyze a log file
logcrux /var/log/syslog

# Analyze only the last hour
logcrux /var/log/nginx/access.log --last 1h

# Raise the AI confidence threshold
logcrux /var/log/auth.log --threshold 0.7

# Output as JSON (for scripting)
logcrux /var/log/syslog --json

# Read from stdin
tail -f /var/log/syslog | logcrux

# Use a custom config file
logcrux /var/log/syslog --config /etc/logcrux/logcrux.yaml

# Verbose / debug output
logcrux /var/log/syslog --verbose

# Show version
logcrux --version        # or -V
```

**Exit codes:** `0` = clean, `3` = info/warning found, `4` = critical incident found.

### How you invoke it

The examples above assume `logcrux` is on your `PATH`. Whether it is
depends on how you installed it:

| installed with | invoke as |
|---|---|
| `uv tool install` or `pipx` | `logcrux ...`, already on `PATH` |
| `pip` into a venv | `~/.venvs/logcrux/bin/logcrux ...`, or activate the venv first |
| no install, one-off run | `uvx logcrux ...` |

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

### Application Frameworks

| Format | `--format` name | Default paths | Detects |
|--------|----------------|---------------|---------|
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
| yum / dnf | `yum` | `/var/log/dnf.log` | Transaction errors |
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

| Metric | Value |
|--------|-------|
| Throughput | ~100 K events analyzed end to end in ~2.4 s (incl. startup) |
| AI inference | ~100 ms per incident |
| Memory | ~190 MB baseline (runtime + models), plus ~2.5 KB per event |
| Model load | ~1.2 s on first run (cached after) |

Measured with logcrux 0.9.0 against a 101 K-line nginx access log;
throughput is hardware-dependent, the memory shape is not.

Events are held in memory, so peak usage scales with the number of events
parsed, not the file size on disk: ~100 K events costs roughly 440 MB. For
logs beyond that, use `--last` to limit the time window (or pre-filter with
`tail`/`grep`) rather than raising `security.max_file_size_mb`.

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
modify, and redistribute, including commercially, with attribution.

---

📖 Docs: [logcrux.com](https://logcrux.com) · 🐛 Issues: [GitHub](https://github.com/ravipatip/logcrux/issues) · 📦 [PyPI](https://pypi.org/project/logcrux/)
