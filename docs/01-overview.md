# logcrux Overview

## What is logcrux?

**logcrux** is an intelligent, fully local log analyzer that detects anomalies, security incidents, and system failures without requiring external APIs, cloud connectivity, or manual configuration. It covers Linux/Unix system logs plus 200+ web server, database, container, cloud, and security formats that are largely OS-agnostic, then produces human-readable incident summaries with confidence scores and remediation guidance.

## Why logcrux?

### The Problem

Modern Linux systems generate logs across dozens of services:
- **System logs** (syslog, kernel, audit)
- **Web servers** (Nginx, Apache)
- **Databases** (PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch)
- **Message queues** (Kafka, RabbitMQ)
- **Security services** (SSH, fail2ban, firewall)
- **Middleware** (Gunicorn, PHP-FPM, Tomcat)
- **Mail & other services** (Postfix, Dovecot, Squid)

Sifting through these manually is time-consuming and error-prone. Traditional tools either:
- Require extensive configuration upfront (e.g., complex regex rules)
- Depend on cloud APIs for intelligence (privacy/compliance concerns)
- Don't understand context (they flag isolated warnings as critical)
- Lack AI-driven categorization (is this an auth breach or just a locked account?)

### The Solution

logcrux provides:

1. **Format Auto-Detection** — Identifies log format automatically (syslog, JSON, custom formats) from the file path and sample
2. **Statistical Analysis** — Detects error rate spikes, event bursts, and specific patterns (OOM, disk full, failed auth sequences)
3. **Contextual Baselines** — Compares current behavior against historical norms using exponential smoothing
4. **AI Classification** — Uses a local classification model to categorize incidents into 7 categories (OOM, auth breach, HTTP overload, disk full, service crash, config error, network issue)
5. **Local Processing** — No cloud dependencies; all analysis happens on your machine
6. **Rich Output** — Incident summaries with confidence scores, findings, and remediation steps

## How logcrux Works (High Level)

### The Analysis Pipeline

```
Log File
   ↓
[Format Detection] — Identifies parser (nginx, syslog, mysql, etc.)
   ↓
[Parsing] — Extracts timestamp, severity, source, message
   ↓
[Statistical Analysis] — Detects patterns: bursts, spikes, auth failures, OOM, disk full
   ↓
[AI Inference] — Classifies incident into 7 categories using ONNX models
   ↓
[Correlation] — Deduplicates overlapping signals
   ↓
[Summarization] — Combines findings, assigns severity (CLEAN/INFO/WARNING/CRITICAL)
   ↓
[Output] — Renders to terminal or JSON
```

### Key Concepts

#### ParsedEvent
Each log line becomes a `ParsedEvent`:
```python
ParsedEvent(
    timestamp: datetime | None,
    severity: Severity,           # debug, info, warning, error, critical, unknown
    source: str,                  # e.g., "nginx", "sshd", "postgres"
    message: str,                 # Log message text
    raw: str,                     # Original line
    line_number: int,
    extra: dict                   # Format-specific fields (HTTP status, user, IP, etc.)
)
```

#### AnomalySignal
Statistical analysis produces signals:
```python
AnomalySignal(
    kind: str,                    # error_burst, rate_spike, auth_failure_cluster, oom_event, etc.
    window: TimeWindow,           # (start, end, duration)
    event_count: int,             # Events in this window
    baseline_count: float,        # Expected based on history
    severity: Severity,
    representative_events: List   # Sample events for user review
)
```

#### IncidentSummary
Final output for users:
```python
IncidentSummary(
    level: "CRITICAL" | "WARNING" | "INFO" | "CLEAN",
    title: str,                   # "Successful brute-force attack on SSH"
    findings: List[Finding],      # Detailed breakdown
    confidence: float,            # 0.0-1.0
    category: str,                # oom, auth_brute_force, http_overload, etc.
    remediation: str,             # Steps to fix
    elapsed_seconds: float,       # How long analysis took
)
```

## Core Features

### 1. Format Auto-Detection (209 parsers)

Automatically detects and parses:
- **System & Auth**: Syslog, journald, kernel (dmesg/kern.log), audit, cron, sudo, dhcp, sssd, krb5kdc
- **Web servers**: Nginx (access + error + JSON), Apache (access + error), Gunicorn, uWSGI, Uvicorn, Werkzeug, Puma, Caddy, Traefik, Envoy, Kong, lighttpd, HAProxy, Squid, AWS ALB
- **FTP & file transfer**: FTP (ftpd), vsftpd
- **Databases**: PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch, Cassandra, ClickHouse, MSSQL, Oracle, CockroachDB, pgBouncer, Patroni (Postgres HA), Neo4j, HBase, Hive, Flink, Druid, Trino, Spark, Hadoop, Solr
- **Containers & Cloud-Native**: Docker, Kubernetes, CRI (containerd), klog, klog-JSON, OTLP, OpenTelemetry Collector (otel), cloud-init, CloudWatch, Fluent Bit/Fluentd, CloudTrail, GCP Logging, VPC Flow, S3 access, GitLab, Terraform, GitHub Actions, LXC, docker-compose (composelog), Kubernetes audit (kubeaudit), Vault audit (vaultaudit)
- **Security / SIEM**: SSH (secure), fail2ban, UFW, AppArmor, auditd, CEF, LEEF, GELF (Graylog), Zeek, Suricata, Wazuh, ModSecurity, Snort, Cisco ASA, Palo Alto, FortiGate, pfSense, Falco, osquery, Okta, Azure Activity, Keycloak, FreeRADIUS, ClamAV
- **Observability**: Prometheus logfmt, Logrus, Pino, Bunyan, Winston, Serilog, Logstash, Filebeat, Datadog, Telegraf, Kibana, Zabbix, Nagios, Python stdlib logging (pylogging)
- **Mail**: Postfix, Dovecot, Exim, Sendmail, OpenSMTPD, rspamd, SpamAssassin, OpenDKIM
- **Application frameworks**: Spring Boot, Log4j, Jetty, WildFly, PHP error log, Laravel, Django, Rails, Go stdlib, Elixir/Phoenix, Airflow, Sidekiq, Celery, Ansible, Jenkins
- **Message queues**: Kafka, RabbitMQ, NATS, Mosquitto, Pulsar, ActiveMQ
- **Storage / Virtualization**: Ceph, ZFS, mdadm, GlusterFS, libvirt, Podman, QEMU/KVM, VMware ESXi, MinIO
- **Network / DNS**: BIND9 (named), PowerDNS, Unbound, dnsmasq, Pi-hole, FRR, MikroTik, UniFi, OpenVPN, WireGuard, Tailscale, strongSwan, wpa_supplicant, Cloudflare, CloudFront, IIS
- **Build / Package management**: dpkg, apt (apthistory), yum/dnf, pip, npm, Maven, Gradle, Bazel, Certbot
- **Config management**: Puppet, Chef, SaltStack
- **Linux daemons**: rsyslog, syslog-ng, D-Bus, polkit, snapd, bluetoothd, Avahi, Asterisk, Chrony/NTP, CUPS, Samba, OpenLDAP, keepalived, firewalld, NetworkManager, smartd, CoreDNS, HashiCorp (Consul/Vault/Nomad), etcd, ZooKeeper, monit, supervisord (supervisor), rsyncd, JVM GC (jvmgc), Xorg, Gitea, Nextcloud

Plus a generic fallback for unrecognized formats.

### 2. Statistical Analysis

Five analysis engines detect:

- **Error Bursts** — Sudden spike in error-severity events
- **Rate Spikes** — Unexpected increase in total event frequency
- **Auth Failures** — Sequences of failed authentication attempts
- **Specific Events** — OOM kills, disk full, service crashes, tunnel anomalies, proxy denials
- **Correlation** — Deduplicates overlapping signals to avoid noise

### 3. AI Inference

A local classification model classifies incident messages into 7 categories:

| Category | What It Means | Example |
|----------|---------------|---------|
| **OOM** | Out-of-memory (kernel kills a process) | "Killed process 1234 (app): out of memory" |
| **Auth Brute Force** | Many failed login attempts | "Invalid user X from Y [preauth]" × 100 |
| **HTTP Overload** | Web server overloaded/cascading errors | "502 Bad Gateway", "connection refused" × 50 |
| **Disk Full** | Filesystem capacity exceeded | "No space left on device" |
| **Service Crash** | Process/daemon crashed unexpectedly | "exited with signal 11 (SIGSEGV)" |
| **Config Error** | Bad configuration causes failures | "syntax error at line 5", "invalid option" |
| **Network Issue** | Network connectivity problem | "Connection reset by peer", "Temporary failure in name resolution" |

### 4. Baseline Tracking

Compares current behavior against historical norms:
- Stores baseline event rates per format per time window
- Uses **exponential smoothing** (α=0.2) for online updates
- Reports baseline vs. current for context
- Gracefully handles new formats (no baseline yet = lower confidence)

### 5. Local State Management

SQLite database tracks:
- **Run history** — Previous analysis results
- **Baselines** — Event rate averages by format
- **Optional** — Can be disabled with `--no-baseline` flag

## Command-Line Usage

### Basic

```bash
logcrux /var/log/syslog              # Analyze a file
logcrux < /var/log/syslog            # Read from stdin
tail -f /var/log/syslog | logcrux    # Tail and analyze
```

### Time Window

```bash
logcrux /var/log/syslog --last 1h    # Last 1 hour
logcrux /var/log/syslog --last 30m   # Last 30 minutes
logcrux /var/log/syslog --last 2d    # Last 2 days
```

### Override Detection

```bash
logcrux /var/log/syslog --format nginx   # Force Nginx parser
logcrux /var/log/syslog --format mysql   # Force MySQL parser
```

### Adjust Confidence

```bash
logcrux /var/log/syslog --threshold 0.7  # Stricter (fewer results)
logcrux /var/log/syslog --threshold 0.2  # Lenient (more results)
```

### Output & Options

```bash
logcrux /var/log/syslog --json           # JSON output (for programmatic use)
logcrux /var/log/syslog --no-baseline    # Skip baseline comparison
logcrux /var/log/syslog --config my.yaml # Custom config file
logcrux /var/log/syslog --verbose        # Debug logging
logcrux --version                        # Show version
```

## Output Example

```
╭─ logcrux / 2026-06-20 16:45:22 ─────────────────────────────────────────────╮
│ CRITICAL: Successful brute-force attack on SSH                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ Analysis Results                                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│ Log File: /var/log/auth.log                                                │
│ Format: secure (SSH)                                                        │
│ Parser: SecureParser                                                        │
│ Time Range: 2026-06-20 15:45:00 to 16:45:22 (1h)                           │
│ Parsed: 427 events                                                          │
│ Analysis took 0.23s                                                         │
│                                                                              │
│ Findings                                                                     │
│ ────────                                                                     │
│ • 47 failed SSH login attempts from 192.168.1.100 in 5-min window           │
│   Baseline: 2 attempts/hour. This is 5.6x higher.                          │
│                                                                              │
│ • Attack source: 192.168.1.100 (consistent attacker)                       │
│   Targeted users: root, admin, test (common default accounts)              │
│                                                                              │
│ • 1 successful login at 16:44:12 from 192.168.1.100 (post-attack)          │
│   Indicates account compromise.                                             │
│                                                                              │
│ Category: Auth Brute Force (confidence: 0.92)                              │
│                                                                              │
│ Remediation                                                                  │
│ ───────────                                                                  │
│ 1. Block attacker IP immediately:                                          │
│    sudo ufw insert 1 deny from 192.168.1.100                               │
│                                                                              │
│ 2. Reset password for compromised accounts (root, admin, test)             │
│                                                                              │
│ 3. Audit login activity:                                                   │
│    grep "Accepted" /var/log/auth.log | tail -20                            │
│                                                                              │
│ 4. Review other active connections:                                        │
│    w -h                                                                      │
│                                                                              │
│ 5. Consider time-based rate limiting in sshd_config:                       │
│    MaxAuthTries 3 (or lower)                                               │
│    MaxSessions 2                                                             │
│    LoginGraceTime 20                                                        │
│                                                                              │
╰─────────────────────────────────────────────────────────────────────────────╯
```

## Exit Codes

- **0** — Analysis complete, no incidents found (CLEAN)
- **3** — Analysis complete, info/warning level incidents found
- **4** — Analysis complete, critical incidents found
- **1** — Error during analysis (file not found, permission denied, etc.)

This allows automation:
```bash
logcrux /var/log/syslog && echo "All clear" || echo "Incidents detected"
```

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────────┐
│                           CLI Layer                             │
│                      (Typer + argparse)                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                      Parser Registry                            │
│            (Auto-detect format from path/sample)               │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    Format-Specific Parsers                      │
│           (209 parsers: Nginx, MySQL, Syslog, etc.)            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   Statistical Analysis Engines                  │
│      (Burst, Rate, Auth, Anomaly, Proxy, Correlation)          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                      AI Inference (ONNX)                        │
│          (local classifier + grouper for clustering)            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    Summarization Engine                         │
│         (Combine signals + inference → incident summary)        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                      Output Rendering                           │
│         (Rich terminal output or JSON for automation)           │
└─────────────────────────────────────────────────────────────────┘
```

## Next Steps

- Read **[Architecture](./02-architecture.md)** for an in-depth technical design
- See **[Supported Log Types](./06-supported-log-types.md)** for the complete list of parsers
- Check **[Development Guide](./19-development.md)** to set up a development environment
- Visit **[Troubleshooting](./21-troubleshooting.md)** if something isn't working as expected

---

**Last Updated:** July 2026
