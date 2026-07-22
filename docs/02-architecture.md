# Architecture

## System Overview

logcrux is a modular log analysis system with seven main layers:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. CLI Layer (cli.py)                                       │
│    - Argument parsing                                       │
│    - Input handling (file/stdin)                           │
│    - Temporal filtering (--last flag)                       │
│    - Output routing                                         │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Parser Detection (parsers/registry.py)                   │
│    - Path-based hints (e.g., /var/log/auth.log)            │
│    - Sample-based format recognition                       │
│    - Parser selection (209 available)                       │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Parsing Layer (parsers/*.py)                             │
│    - Extract timestamp, severity, source, message          │
│    - Handle format-specific quirks                          │
│    - Return ParsedEvent objects                             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Analysis Engines (analysis/*.py)                         │
│    - Error burst detection                                 │
│    - Rate spike detection                                  │
│    - Anomaly pattern matching (OOM, disk full, auth)       │
│    - Proxy anomaly detection                               │
│    - Signal correlation (deduplication)                    │
│    → Returns AnomalySignal list                            │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. State Management (state/*.py)                            │
│    - Load baseline event rates from SQLite                 │
│    - Compare current stats against baseline                │
│    - Update baseline with exponential smoothing            │
│    - Store run history                                      │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. AI Inference (inference/*.py)                            │
│    - Load ONNX models (classifier + grouper)               │
│    - Classify incident messages (7 categories)             │
│    - Cluster related events                                │
│    - Return InferenceResult with confidence                │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 7. Summarization & Output (summarizer/, output/)            │
│    - Combine analysis signals + inference results          │
│    - Assign severity level (CLEAN/INFO/WARNING/CRITICAL)   │
│    - Generate findings and remediation                     │
│    - Render to terminal (Rich) or JSON                     │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
logcrux/
├── cli.py                 # Entry point, argument parsing, orchestration
├── models.py              # Data structures (ParsedEvent, AnomalySignal, etc.)
├── config.py              # Configuration loading (YAML)
├── security.py            # Path validation, duration parsing
├── exceptions.py          # Custom exceptions
│
├── parsers/               # 209 parsers (208 format-specific + generic)
│   ├── base.py            # LogParser abstract base class
│   ├── registry.py        # Auto-detection and parser selection
│   ├── syslog.py          # Generic syslog
│   ├── nginx_access.py    # Nginx access logs
│   ├── nginx_error.py     # Nginx error logs
│   ├── apache_access.py   # Apache access logs
│   ├── apache_error.py    # Apache error logs
│   ├── mysql.py           # MySQL error logs
│   ├── postgresql.py      # PostgreSQL logs
│   ├── mongodb.py         # MongoDB JSON/legacy format
│   ├── redis.py           # Redis logs
│   ├── elasticsearch.py   # Elasticsearch logs
│   ├── docker.py          # Docker logs
│   ├── kubernetes.py      # Kubernetes logs
│   ├── journald.py        # systemd journal
│   ├── kernel.py          # Kernel/dmesg
│   ├── secure.py          # SSH auth (syslog-tagged)
│   ├── fail2ban.py        # fail2ban
│   ├── ufw.py             # UFW firewall
│   ├── cron.py            # cron logs
│   ├── sudo.py            # sudo logs
│   ├── audit.py           # auditd logs
│   ├── gunicorn.py        # Gunicorn WSGI server
│   ├── tomcat.py          # Tomcat application server
│   ├── phpfpm.py          # PHP-FPM
│   ├── kafka.py           # Kafka
│   ├── rabbitmq.py        # RabbitMQ
│   ├── postfix.py         # Postfix mail
│   ├── dovecot.py         # Dovecot mail
│   ├── exim.py            # Exim mail
│   ├── haproxy.py         # HAProxy load balancer
│   ├── squid.py           # Squid proxy
│   ├── openvpn.py         # OpenVPN
│   ├── dnsmasq.py         # Dnsmasq DNS/DHCP
│   ├── named.py           # BIND (named) DNS
│   ├── chrony.py          # Chrony/NTP
│   ├── samba.py           # Samba SMB
│   ├── dhcpd.py           # DHCP server
│   ├── ftp.py             # FTP server
│   ├── vsftpd.py          # vsftpd FTP
│   └── generic.py         # Fallback parser
│
├── analysis/              # Statistical anomaly detection
│   ├── engine.py          # Orchestrator; calls all modules
│   ├── burst.py           # High-frequency event bursts
│   ├── error_rate.py      # Error rate spikes vs baseline
│   ├── anomaly.py         # Pattern matching (OOM, disk full, auth)
│   ├── proxy.py           # Proxy-specific patterns
│   └── correlation.py     # Signal deduplication
│
├── inference/             # AI-powered classification
│   ├── engine.py          # Loads ONNX models, coordinates
│   ├── classifier.py      # 7-way incident classification
│   ├── grouper.py         # Clusters related events
│   └── models/            # ONNX model files (INT8-quantized, ~22MB each)
│       ├── classifier.onnx
│       └── grouper.onnx
│
├── state/                 # Persistence layer
│   ├── db.py              # SQLite database interface
│   ├── baseline.py        # Event rate baselines
│   └── history.py         # Run history
│
├── summarizer/            # Final output generation
│   └── engine.py          # Combines signals + inference
│
├── output/                # Rendering
│   └── renderer.py        # Rich terminal + JSON output
│
└── __init__.py            # Package metadata
```

## Data Flow Detail

### 1. CLI Entry Point (`cli.py`)

```python
@app.command()
def analyze(
    path: Optional[Path],           # Log file or None (stdin)
    last: Optional[str],            # Time window: "30m", "1h", "2d"
    format_override: Optional[str], # Force parser type
    threshold: Optional[float],     # AI confidence threshold
    no_baseline: bool,              # Skip baseline tracking
    json_output: bool,              # JSON output
    config_path: Optional[Path],    # Custom config file
    verbose: bool,                  # Debug logging
) -> None:
```

**Actions:**
1. Load config (YAML or defaults)
2. Validate log file path (security checks)
3. Read log data (file or stdin)
4. Apply temporal filter if `--last` specified
5. Call analysis pipeline
6. Render output (Rich or JSON)
7. Exit with appropriate code

### 2. Parser Registry & Detection (`parsers/registry.py`)

**Goal:** Identify log format from path and/or sample

```python
def detect_parser(path: Optional[Path], sample_lines: list[str]) -> LogParser:
    """Select best parser for log file."""
```

**Algorithm:**
1. Try path-specific detection first (e.g., `/var/log/auth.log` → SecureParser)
2. Try each parser in `_PARSERS` order:
   - Call `Parser.can_parse(path, sample_lines)` on each
   - Return first that matches
3. Fall back to `GenericParser` if none match

**Parser Order Matters:**
- Path-specific (Kubernetes, Docker, journald) checked first
- Web server error logs before access logs (more distinctive)
- Proxy logs before web access (share CLF but have differences)
- Syslog-tagged services before generic syslog
- Structured logs (JSON-based) have order independence
- Generic catch-all last

### 3. Parsing Layer (`parsers/base.py` + specific parsers)

Each parser inherits from `LogParser`:

```python
class LogParser(ABC):
    FORMAT_NAME: str = "format_name"
    
    @classmethod
    def can_parse(cls, path: Optional[Path], sample_lines: list[str]) -> bool:
        """Return True if this parser recognizes the format."""
    
    def parse_line(self, line: str, line_number: int) -> Optional[ParsedEvent]:
        """Parse one log line into a ParsedEvent."""
```

**Input:** Raw log lines  
**Output:** `ParsedEvent` objects
```python
ParsedEvent(
    timestamp: datetime | None,
    severity: Severity,              # debug, info, warning, error, critical, unknown
    source: str,                     # "nginx", "sshd", "postgres", etc.
    message: str,                    # Log message text (cleaned)
    raw: str,                        # Original line
    line_number: int,
    extra: dict[str, Any]            # Format-specific: http_status, user, ip, etc.
)
```

**Example (NginxAccessParser):**
```
192.168.1.1 - - [20/Jun/2026:16:45:22 +0000] "GET /api/v1 HTTP/1.1" 200 1234
    ↓
ParsedEvent(
    timestamp=datetime(2026, 6, 20, 16, 45, 22),
    severity=Severity.INFO,
    source="nginx",
    message="GET /api/v1 HTTP/1.1 - 200",
    extra={"ip": "192.168.1.1", "method": "GET", "path": "/api/v1", "status": 200, ...}
)
```

### 4. Analysis Engines (`analysis/engine.py` + modules)

**Goal:** Detect anomalies statistically

```python
def run_analysis(
    parsed_events: list[ParsedEvent],
    log_path: str,
    parser_format: str,
    config: Config,
    baseline: dict[str, float],      # Historical rates
) -> AnalysisResult:
```

**Engines (called in sequence):**

1. **Burst Analysis** (`analysis/burst.py`)
   - Detects windows where event frequency spikes
   - Compares within-window frequency to overall average
   - Returns `AnomalySignal(kind="error_burst", ...)`

2. **Error Rate Analysis** (`analysis/error_rate.py`)
   - Focuses on error/critical-severity events
   - Detects spikes in proportion of errors
   - Returns `AnomalySignal(kind="rate_spike", ...)`

3. **Anomaly Patterns** (`analysis/anomaly.py`)
   - Specific pattern matching:
     - **OOM events:** Kernel "Killed process" messages
     - **Disk full:** "No space left on device"
     - **Auth failures:** Sequences of failed login attempts
     - **Service crashes:** Process termination signals
   - Returns typed signals: `AnomalySignal(kind="oom_event", ...)`

4. **Proxy Anomalies** (`analysis/proxy.py`)
   - Proxy/load-balancer specific:
     - **Denial clusters:** HTTP 403/401 from same source
     - **Tunnel anomalies:** Proxy connection failures
   - Returns `AnomalySignal(kind="proxy_denial_cluster", ...)`

5. **Correlation** (`analysis/correlation.py`)
   - Deduplicates overlapping signals
   - If signals overlap in time and relate to same issue, merges them
   - Prevents reporting the same incident twice

**Output:** `AnalysisResult`
```python
AnalysisResult(
    log_path: str,
    parser_format: str,
    parsed_count: int,
    skipped_count: int,
    time_range: TimeWindow | None,
    signals: list[AnomalySignal]     # All detected anomalies
)
```

### 5. State Management (`state/db.py`, `baseline.py`)

**Goal:** Track historical context to improve detection

```python
# Load baseline
baseline = get_baseline(db, log_format)
# Example: {"syslog": 45.2, "nginx": 100.5}  # events/minute

# Use in analysis
baseline_count = baseline.get(log_format) * window_minutes
current_burst = analyze_burst(events)
if current_burst > baseline_count * spike_factor:
    # Alert
```

**Baseline Update (exponential smoothing):**
```
baseline_new = α × current_rate + (1 - α) × baseline_old
# α = 0.2 (20% weight to current, 80% to history)
```

This prevents baselines from being skewed by a single anomaly.

**State Location:**
```
~/.local/share/logcrux/state.db        # SQLite database
  ├── baselines                         # (format, event_rate)
  └── run_history                       # (log_path, format, incident_level, timestamp)
```

### 6. AI Inference (`inference/engine.py`)

**Goal:** Classify incidents into 7 categories with confidence

**Models:**
- **Classifier:** 7-way local classification model
  - Input: Representative incident messages
  - Output: Probability distribution over 7 categories
  - Confidence: max softmax value
  - Threshold: 0.35 (configurable)

- **Grouper:** Local sentence-embedding model + cosine clustering
  - Input: All relevant event messages
  - Output: Clustered groups (cosine ≥ 0.75)
  - Used to group related events for display

**Classification Logic:**
```python
def classify(representative_messages: list[str]) -> InferenceResult:
    logits = classifier_model(representative_messages)
    softmax = torch.softmax(logits, dim=-1)
    confidence = softmax.max()
    category = CATEGORIES[softmax.argmax()]
    
    if confidence < threshold:
        category = IncidentCategory.UNKNOWN
    
    return InferenceResult(
        category=category,
        confidence=float(confidence),
        grouped_event_clusters=grouper_model(all_messages)
    )
```

**Categories:**
| Category | When Triggered | Confidence Requirement |
|----------|-------|---|
| OOM | Process killed by kernel OOM | 0.35+ |
| Auth Brute Force | Multiple failed auth attempts from same source | 0.35+ |
| HTTP Overload | Web server returning 5xx or connection errors | 0.35+ |
| Disk Full | Filesystem out of space | 0.35+ |
| Service Crash | Process/daemon crashed | 0.35+ |
| Config Error | Configuration syntax/option errors | 0.35+ |
| Network Issue | Connectivity, DNS, or network-layer failures | 0.35+ |

### 7. Summarization (`summarizer/engine.py`)

**Goal:** Combine analysis signals + inference into one incident summary

```python
def summarize(
    analysis_result: AnalysisResult,
    inference_result: Optional[InferenceResult],
    config: Config,
) -> IncidentSummary:
```

**Decision Logic:**

1. **No signals detected:**
   - Level = CLEAN, title = "No anomalies detected"

2. **Signals detected, no inference:**
   - Infer category from signal types:
     - `oom_event` → OOM
     - `auth_failure_cluster` → Auth Brute Force
     - `disk_full` → Disk Full
     - `service_crash` → Service Crash
     - `error_burst` / `rate_spike` → UNKNOWN
   - Level = WARNING or CRITICAL based on signal severity

3. **Signals detected + inference:**
   - **Deterministic signal wins**: If a specific signal (OOM, auth, disk, crash), use that category
   - **Generic signal + AI**: If only burst/spike signals, use AI classification
   - Confidence = inference confidence
   - Level = CRITICAL if confidence > 0.7, else WARNING

4. **Generate findings:**
   - Summarize each signal with representative events
   - Include baseline comparison
   - Highlight outliers and patterns

5. **Generate remediation:**
   - Category-specific steps (e.g., "reset SSH password" for auth brute force)
   - General triage steps

**Output:** `IncidentSummary`
```python
IncidentSummary(
    level: Literal["CRITICAL", "WARNING", "INFO", "CLEAN"],
    title: str,
    findings: list[Finding],
    confidence: float,                # 0.0-1.0
    category: IncidentCategory,
    remediation: Optional[str],
    log_path: str,
    parser_format: str,
    analyzed_at: datetime,
    parsed_count: int,
    elapsed_seconds: float,
)
```

### 8. Output Rendering (`output/renderer.py`)

**Terminal Output (Rich):**
```
╭─ logcrux / 2026-06-20 16:45:22 ─────────────────────────────╮
│ CRITICAL: Successful brute-force attack on SSH              │
├─────────────────────────────────────────────────────────────┤
│ Findings                                                     │
│ • 47 failed attempts from 192.168.1.100                     │
│ • 1 successful login (account compromised)                  │
│ Category: Auth Brute Force (0.92 confidence)                │
│ Remediation: Block IP, reset passwords, audit activity...  │
╰─────────────────────────────────────────────────────────────╯
```

**JSON Output:**
```json
{
  "analysis_id": "uuid",
  "level": "CRITICAL",
  "title": "Successful brute-force attack on SSH",
  "findings": [...],
  "confidence": 0.92,
  "category": "auth_brute_force",
  "remediation": "...",
  "log_path": "/var/log/auth.log",
  "parser_format": "secure",
  "analyzed_at": "2026-06-20T16:45:22",
  "parsed_count": 427,
  "elapsed_seconds": 0.23
}
```

## Key Design Decisions

### 1. Parser Order Matters
Parsers are ordered by specificity. A generic syslog parser could match almost anything, so format-specific parsers (Nginx, MySQL) are checked first. This prevents false positives.

### 2. Graceful Degradation
- If ONNX models aren't found, inference is skipped (warnings logged, analysis continues)
- If baseline DB is unavailable, analysis works without baseline comparison
- If config file is missing, hardcoded defaults are used

### 3. Representative Events Over Raw Counts
Instead of feeding the entire incident message set to the AI, we select 2-5 representative events. This matches how the model was trained (one message per example) and avoids overwhelming the context.

### 4. Exponential Smoothing for Baselines
Baselines are updated with low weight (α=0.2) to prevent a single anomaly from skewing future thresholds. This makes the system robust to occasional spikes.

### 5. Category Precedence
Specific patterns (OOM, auth failure) override generic AI classification. If the logs literally say "killed for OOM," we don't consult the AI—we report OOM. This reduces false positives from the AI.

### 6. Correlation Before Summarization
Multiple overlapping signals (e.g., burst + rate spike on the same event source) are deduplicated before summarization. This prevents reporting the same incident twice.

### 7. Confidence Thresholds
- AI prediction < 0.35: Marked as UNKNOWN (below near-random for 7 classes)
- Incident confidence > 0.7: CRITICAL level
- Incident confidence 0.35-0.7: WARNING level

### 8. Time Windows Are Sliding
Analysis doesn't use fixed hourly buckets. Instead, events are grouped into windows based on when bursts actually occur, allowing natural clustering of related events.

## Module Dependencies

```
cli.py (entry point)
  ├─ config.py (load settings)
  ├─ parsers/registry.py (detect format)
  │   └─ parsers/*.py (209 parsers)
  ├─ analysis/engine.py (detect anomalies)
  │   ├─ analysis/burst.py
  │   ├─ analysis/error_rate.py
  │   ├─ analysis/anomaly.py
  │   ├─ analysis/proxy.py
  │   └─ analysis/correlation.py
  ├─ state/db.py (load baseline)
  │   ├─ state/baseline.py
  │   └─ state/history.py
  ├─ inference/engine.py (AI classification)
  │   ├─ inference/classifier.py
  │   └─ inference/grouper.py
  ├─ summarizer/engine.py (combine signals)
  └─ output/renderer.py (render output)
```

All modules interact through data models in `models.py` (ParsedEvent, AnomalySignal, IncidentSummary, etc.).

---

**Last Updated:** July 2026
