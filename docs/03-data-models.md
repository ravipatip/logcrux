# Data Models

logcrux uses Pydantic-based data models to ensure type safety and validation throughout the analysis pipeline. This document describes all core models.

## Core Models

### Severity Enum

```python
class Severity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
```

**Usage:** Indicates the severity of a log event, parsed from the log entry.

**Severity Ordering (Low → High):**
```
DEBUG < INFO < WARNING < ERROR < CRITICAL
UNKNOWN (unclassified)
```

---

### ParsedEvent

Represents a single parsed log line.

```python
class ParsedEvent(BaseModel):
    timestamp: datetime | None          # When the event occurred
    severity: Severity                  # Event severity level
    source: str                         # Source (app name, service)
    message: str                        # Log message text
    raw: str                            # Original unparsed line
    line_number: int                    # Position in original file
    extra: dict[str, Any] = {}          # Format-specific fields
```

**Example (Nginx Access):**
```python
ParsedEvent(
    timestamp=datetime(2026, 6, 20, 16, 45, 22),
    severity=Severity.INFO,
    source="nginx",
    message="GET /api/v1 HTTP/1.1 - 200",
    raw='192.168.1.1 - - [20/Jun/2026:16:45:22 +0000] "GET /api/v1 HTTP/1.1" 200 1234',
    line_number=1234,
    extra={
        "ip": "192.168.1.1",
        "method": "GET",
        "path": "/api/v1",
        "protocol": "HTTP/1.1",
        "status": 200,
        "bytes_sent": 1234,
        "referer": "-",
        "user_agent": "Mozilla/5.0"
    }
)
```

**Example (PostgreSQL Error):**
```python
ParsedEvent(
    timestamp=datetime(2026, 6, 20, 16, 45, 22, 123000),
    severity=Severity.ERROR,
    source="postgresql",
    message="syntax error at or near ':'",
    raw='2026-06-20 16:45:22.123 UTC [12345] user@mydb [SELECT] ERROR: syntax error',
    line_number=5678,
    extra={
        "pid": 12345,
        "user": "user",
        "database": "mydb",
        "statement": "SELECT",
        "error_code": "42601"
    }
)
```

---

### TimeWindow

Represents a time range for analysis.

```python
class TimeWindow(BaseModel):
    start: datetime                     # Window start time
    end: datetime                       # Window end time
    duration_seconds: float             # Duration in seconds
```

**Example:**
```python
TimeWindow(
    start=datetime(2026, 6, 20, 16, 40, 0),
    end=datetime(2026, 6, 20, 16, 45, 0),
    duration_seconds=300.0
)
```

---

### AnomalySignal

Represents a detected anomaly.

```python
class AnomalySignal(BaseModel):
    kind: Literal[
        "error_burst",              # High-frequency errors
        "rate_spike",               # Unusual increase in event volume
        "auth_failure_cluster",     # Multiple failed auth attempts
        "oom_event",                # Out-of-memory kill
        "service_crash",            # Process termination/crash
        "disk_full",                # Filesystem full error
        "tunnel_anomaly",           # VPN/tunnel connection issue
        "proxy_denial_cluster",     # Multiple proxy denials
        "unknown",                  # Unclassified anomaly
    ]
    window: TimeWindow              # When the anomaly occurred
    event_count: int                # Events in this window
    baseline_count: float | None    # Expected count from baseline
    severity: Severity              # Overall severity
    representative_events: list[ParsedEvent]  # Sample events
```

**Kinds Explained:**

| Kind | Meaning | Example |
|------|---------|---------|
| **error_burst** | Sudden spike in error-severity events | 50 errors in 5 min (baseline: 2) |
| **rate_spike** | Overall event frequency increases | 1000 events/min (baseline: 100) |
| **auth_failure_cluster** | Multiple failed authentication attempts | 47 failed SSH logins in 5 min from same IP |
| **oom_event** | Process killed for out-of-memory | Kernel OOM kill message |
| **service_crash** | Process/daemon terminated unexpectedly | "exited with signal 11 (SIGSEGV)" |
| **disk_full** | Filesystem capacity exceeded | "No space left on device" |
| **tunnel_anomaly** | VPN/tunnel connection error | "TLS error", "tunnel closed" |
| **proxy_denial_cluster** | Multiple proxy denials from source | 10+ HTTP 403/401 from 192.168.1.1 |
| **unknown** | Generic anomaly (catch-all) | Fallback for unclassified patterns |

**Example:**
```python
AnomalySignal(
    kind="auth_failure_cluster",
    window=TimeWindow(
        start=datetime(2026, 6, 20, 16, 40, 0),
        end=datetime(2026, 6, 20, 16, 45, 0),
        duration_seconds=300.0
    ),
    event_count=47,
    baseline_count=2.0,
    severity=Severity.CRITICAL,
    representative_events=[
        # ... 3-5 representative ParsedEvent objects
    ]
)
```

---

### AnalysisResult

Output of the statistical analysis phase.

```python
class AnalysisResult(BaseModel):
    log_path: str                       # Path to analyzed log
    parser_format: str                  # Format detected (e.g., "nginx_access")
    parsed_count: int                   # Total lines parsed
    skipped_count: int                  # Unparseable lines
    time_range: TimeWindow | None       # Time range of events
    signals: list[AnomalySignal]        # Detected anomalies
```

**Example:**
```python
AnalysisResult(
    log_path="/var/log/auth.log",
    parser_format="secure",
    parsed_count=427,
    skipped_count=3,
    time_range=TimeWindow(
        start=datetime(2026, 6, 20, 15, 45, 0),
        end=datetime(2026, 6, 20, 16, 45, 0),
        duration_seconds=3600.0
    ),
    signals=[
        AnomalySignal(...),  # auth_failure_cluster
        AnomalySignal(...),  # oom_event
    ]
)
```

---

### IncidentCategory Enum

```python
class IncidentCategory(str, Enum):
    OOM = "oom"
    AUTH_BRUTE_FORCE = "auth_brute_force"
    HTTP_OVERLOAD = "http_overload"
    DISK_FULL = "disk_full"
    SERVICE_CRASH = "service_crash"
    CONFIG_ERROR = "config_error"
    NETWORK_ISSUE = "network_issue"
    UNKNOWN = "unknown"
```

**Categories:** AI classifier outputs one of these 7 categories (or UNKNOWN if below confidence threshold).

---

### InferenceResult

Output of AI inference.

```python
class InferenceResult(BaseModel):
    category: IncidentCategory          # Classified incident category
    confidence: float                   # 0.0-1.0 confidence score
    correlated_signals: list[str]       # Matching signal kinds
    grouped_event_clusters: list[list[int]]  # Event clusters by similarity
```

**Confidence Interpretation:**
- **0.0-0.14:** Random (1/7 ≈ 14%)
- **0.14-0.35:** Below threshold (classifier output ignored)
- **0.35-0.7:** Moderate confidence (WARNING level)
- **0.7-1.0:** High confidence (CRITICAL level)

**Example:**
```python
InferenceResult(
    category=IncidentCategory.AUTH_BRUTE_FORCE,
    confidence=0.92,
    correlated_signals=["auth_failure_cluster"],
    grouped_event_clusters=[
        [0, 1, 2, 3],   # Cluster 1: "Failed password" messages
        [4, 5, 6],      # Cluster 2: "Invalid user" messages
        [7],            # Cluster 3: "Accepted password" (successful breach)
    ]
)
```

---

### Finding

A single finding in an incident summary.

```python
class Finding(BaseModel):
    headline: str                       # Brief summary
    detail: str | None = None           # Detailed explanation (optional)
```

**Example:**
```python
Finding(
    headline="47 failed SSH login attempts from 192.168.1.100 in 5-min window",
    detail="Baseline: 2 attempts/hour. This is 5.6x higher. Targeted users: root, admin, test (common defaults). Attack pattern: incremental user enumeration."
)
```

---

### IncidentSummary

Final output for users.

```python
class IncidentSummary(BaseModel):
    analysis_id: str                    # Unique ID for this analysis
    level: Literal["CRITICAL", "WARNING", "INFO", "CLEAN"]
    title: str                          # Incident title
    findings: list[Finding]             # Detailed findings
    confidence: float                   # Overall confidence (0.0-1.0)
    category: IncidentCategory          # Incident category
    remediation: str | None = None      # Remediation steps
    log_path: str                       # Analyzed log path
    parser_format: str = "unknown"      # Detected format
    analyzed_at: datetime               # When analysis ran
    parsed_count: int                   # Events parsed
    skipped_count: int = 0              # Events skipped
    elapsed_seconds: float              # Analysis duration
```

**Levels:**
| Level | Meaning | Exit Code |
|-------|---------|-----------|
| **CLEAN** | No anomalies detected | 0 |
| **INFO** | Informational only | 3 |
| **WARNING** | Alert warranted | 3 |
| **CRITICAL** | Immediate action needed | 4 |

**Example:**
```python
IncidentSummary(
    analysis_id="a1b2c3d4-e5f6-4789-0123-456789abcdef",
    level="CRITICAL",
    title="Successful brute-force attack on SSH",
    findings=[
        Finding(
            headline="47 failed SSH login attempts from 192.168.1.100",
            detail="Baseline: 2/hour. This is 5.6x higher."
        ),
        Finding(
            headline="1 successful login post-attack",
            detail="Indicates compromised account."
        ),
    ],
    confidence=0.92,
    category=IncidentCategory.AUTH_BRUTE_FORCE,
    remediation="1. Block IP: sudo ufw insert 1 deny from 192.168.1.100\n2. Reset passwords for root, admin, test\n3. Review /var/log/auth.log for other breaches\n4. Consider fail2ban or rate limiting in sshd_config",
    log_path="/var/log/auth.log",
    parser_format="secure",
    analyzed_at=datetime(2026, 6, 20, 16, 45, 22),
    parsed_count=427,
    skipped_count=0,
    elapsed_seconds=0.23
)
```

---

## Relationship Diagram

```
CLI Input (file/stdin)
    ↓
Parser (using registry)
    ↓ (repeats for each line)
ParsedEvent  ← → extra (format-specific)
    ↓ (accumulates)
list[ParsedEvent]
    ↓
Analysis Engines (burst, error_rate, anomaly, proxy, correlation)
    ↓ (returns)
AnalysisResult
    ├─ signals: list[AnomalySignal]
    │   └─ representative_events: list[ParsedEvent]
    ├─ time_range: TimeWindow
    └─ ...
    ↓
State Management (load baseline, compare)
    ↓
AI Inference (classifier + grouper)
    ↓ (returns if available)
InferenceResult (or None)
    ↓
Summarization (combine analysis + inference)
    ↓ (returns)
IncidentSummary
    ├─ findings: list[Finding]
    ├─ category: IncidentCategory
    └─ level: ("CRITICAL", "WARNING", "INFO", "CLEAN")
    ↓
Output Rendering (Rich terminal or JSON)
    ↓
Console Output + Exit Code
```

## JSON Schema (for programmatic use)

All models are Pydantic-based, enabling JSON serialization:

```python
summary = IncidentSummary(...)
json_str = summary.model_dump_json(indent=2)
```

**Sample JSON:**
```json
{
  "analysis_id": "a1b2c3d4-e5f6-4789-0123-456789abcdef",
  "level": "CRITICAL",
  "title": "Successful brute-force attack on SSH",
  "findings": [
    {
      "headline": "47 failed SSH login attempts from 192.168.1.100",
      "detail": "Baseline: 2/hour. This is 5.6x higher."
    }
  ],
  "confidence": 0.92,
  "category": "auth_brute_force",
  "remediation": "...",
  "log_path": "/var/log/auth.log",
  "parser_format": "secure",
  "analyzed_at": "2026-06-20T16:45:22",
  "parsed_count": 427,
  "skipped_count": 0,
  "elapsed_seconds": 0.23
}
```

## Validation Rules

### ParsedEvent
- `timestamp` can be None (if unparseable)
- `severity` must be a valid Severity enum
- `source` is required (at least service name)
- `message` is required
- `line_number` >= 1

### AnomalySignal
- `event_count` >= 1 (at least one event to trigger)
- `baseline_count` can be None (new format, no baseline yet)
- `representative_events` should have 2-5 events (enough for context)

### IncidentSummary
- `level` determines exit code
- `confidence` in 0.0-1.0 range
- `elapsed_seconds` > 0
- `parsed_count` + `skipped_count` = total lines read

---

**Last Updated:** July 2026
