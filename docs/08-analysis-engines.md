# Analysis Engines

logcrux runs 5 statistical analysis engines in sequence to detect various types of anomalies. Each engine produces `AnomalySignal` objects that are later deduplicated and summarized.

## Overview

```
ParsedEvent List
    ↓
┌─────────────────────┐
│ 1. Burst Analysis   │  → Detects high-frequency events
└─────────────────────┘
    ↓
┌─────────────────────┐
│ 2. Error Rate       │  → Detects error proportion spikes
└─────────────────────┘
    ↓
┌─────────────────────┐
│ 3. Anomaly Patterns │  → Pattern matching (OOM, disk, auth, crash)
└─────────────────────┘
    ↓
┌─────────────────────┐
│ 4. Proxy Anomalies  │  → Proxy-specific patterns
└─────────────────────┘
    ↓
┌─────────────────────┐
│ 5. Correlation      │  → Deduplicates overlapping signals
└─────────────────────┘
    ↓
AnalysisResult(signals=[...])
```

## 1. Burst Analysis (`analysis/burst.py`)

**Goal:** Detect sudden spikes in event frequency.

### Algorithm

1. **Group events by window** (default: 5-minute windows)
   - Create sliding windows across the time range
   - For each window, count events

2. **Calculate baseline frequency**
   - Average events per window across entire log

3. **Detect bursts**
   - If window_events > baseline × burst_multiplier → anomaly
   - Default: 3× baseline triggers alert

4. **Generate signals**
   - Create `AnomalySignal(kind="error_burst", ...)` for bursts

### Example

```
Baseline: 20 events/5-min window
Multiplier: 3.0

Window 1 (16:00-16:05): 22 events      ✓ Normal (22 < 60)
Window 2 (16:05-16:10): 18 events      ✓ Normal (18 < 60)
Window 3 (16:10-16:15): 180 events     ✗ BURST! (180 > 60)
Window 4 (16:15-16:20): 25 events      ✓ Normal (25 < 60)

→ AnomalySignal(
    kind="error_burst",
    window=16:10-16:15,
    event_count=180,
    baseline_count=60.0,
    representative_events=[...]
)
```

### Configuration

```yaml
analysis:
  window_size_minutes: 5        # How large each window is
  burst_multiplier: 3.0         # Alert when > baseline × this
```

### Use Cases

- **Web servers:** Sudden spike in requests (possible DDoS)
- **Databases:** Connection pool exhaustion
- **System logs:** Rapid error loops
- **Syslog:** Service restart loops

---

## 2. Error Rate Analysis (`analysis/error_rate.py`)

**Goal:** Detect increase in proportion of error-severity events (ERROR, CRITICAL).

### Algorithm

1. **For each time window:**
   - Count total events
   - Count error-severity events (ERROR, CRITICAL only)
   - Calculate error proportion: `error_count / total_count`

2. **Compare to baseline**
   - Get historical error proportion
   - If current > baseline × spike_factor → anomaly

3. **Generate signals**
   - Create `AnomalySignal(kind="rate_spike", ...)` for spikes

### Example

```
Baseline error rate: 5% (5 errors per 100 events)

Window 1: 100 events, 5 errors → 5%        ✓ Normal
Window 2: 100 events, 25 errors → 25%      ✗ SPIKE! (25% > 5% × 3.0)
Window 3: 100 events, 30 errors → 30%      ✗ Still high

→ AnomalySignal(
    kind="rate_spike",
    event_count=110,
    baseline_count=10.0,  # 5% of 200
    representative_events=[...]
)
```

### Configuration

```yaml
analysis:
  spike_factor: 3.0             # Alert when error% > baseline% × this
  window_size_minutes: 5
```

### Difference from Burst

- **Burst:** Raw event frequency spike (any severity)
- **Rate spike:** Error proportion spike (focus on health)

A service that suddenly becomes very verbose (many INFO events) triggers burst but not rate spike. A service that fails silently except for errors triggers rate spike.

### Use Cases

- **Application errors:** Code exceptions, unhandled conditions
- **Database errors:** Query failures, locks, timeouts
- **Network issues:** Connection refused, timeouts (ERROR in logs)

---

## 3. Anomaly Pattern Matching (`analysis/anomaly.py`)

**Goal:** Detect specific known-bad patterns via keyword/substring matching.

### Patterns Detected

#### OOM (Out-of-Memory)

**Trigger:** Kernel message like `Killed process \d+.*out of memory`

**Example:**
```
[  234.567890] Out of memory: Kill process 1234 (java) score 100 or sacrifice child
```

**Signal:**
```python
AnomalySignal(
    kind="oom_event",
    severity=Severity.CRITICAL,
    representative_events=[oom_kill_message]
)
```

**Next Step:** Investigate memory usage, OOM killer behavior, app logs.

---

#### Disk Full

**Trigger:** Message containing `No space left on device` or similar

**Example:**
```
/dev/sda1: write error: No space left on device
```

**Signal:**
```python
AnomalySignal(
    kind="disk_full",
    severity=Severity.CRITICAL,
    representative_events=[disk_error]
)
```

**Next Step:** Free disk space, check for log file growth, rotate old logs.

---

#### Service Crash

**Trigger:** Message indicating unexpected process termination, e.g.:
- `exited with signal`
- `Segmentation fault`
- `Bus error`
- `Aborted`

**Example:**
```
nginx: master process exited with code 1
```

**Signal:**
```python
AnomalySignal(
    kind="service_crash",
    severity=Severity.ERROR,
    representative_events=[crash_message]
)
```

**Next Step:** Check core dump, enable coredump debugging, review systemd journal.

---

#### Auth Failure Cluster

**Trigger:** Multiple failed authentication attempts from same source in short time

**Example:**
```
sshd[12345]: Failed password for user root from 192.168.1.100
sshd[12346]: Failed password for user root from 192.168.1.100
sshd[12347]: Failed password for user admin from 192.168.1.100
...×10 more
```

**Algorithm:**
1. Group by source IP + authentication service
2. Count failed auth attempts in window
3. If count > threshold (default: 10) → cluster detected

**Signal:**
```python
AnomalySignal(
    kind="auth_failure_cluster",
    severity=Severity.CRITICAL,
    representative_events=[5_sample_failures]
)
```

**Configuration:**
```yaml
analysis:
  auth_failure_threshold: 10    # Min attempts to trigger
```

**Next Step:** Block IP, reset passwords, audit other accounts.

---

### Implementation Details

All patterns use **case-insensitive substring matching** to catch variations:
- `killed process` matches `Killed process`, `KILLED PROCESS`, etc.
- `no space left` matches `No space left on device`, `NO SPACE LEFT`, etc.

This prevents false negatives from case variations across different systems.

### Code Pattern

```python
def analyze_anomalies(
    events: list[ParsedEvent],
    config: Config,
) -> list[AnomalySignal]:
    signals = []
    
    # Check each event for patterns
    for event in events:
        message_lower = event.message.lower()
        raw_lower = event.raw.lower()
        
        if "killed process" in message_lower and "out of memory" in raw_lower:
            signals.append(AnomalySignal(kind="oom_event", ...))
        
        elif "no space left on device" in message_lower:
            signals.append(AnomalySignal(kind="disk_full", ...))
        
        # ... other patterns
    
    return signals
```

### Use Cases

- **Proactive alerting:** Catch failures before cascade
- **Incident correlation:** OOM kill might cause service crash (both detected)
- **Security:** Auth failure clusters indicate attack

---

## 4. Proxy Anomaly Detection (`analysis/proxy.py`)

**Goal:** Detect proxy/load-balancer-specific patterns (HAProxy, Squid, nginx reverse proxy).

### Patterns Detected

#### Proxy Denial Cluster

**Trigger:** Multiple HTTP 4xx (denial) responses from same source in short time

**Example (HAProxy):**
```
192.168.1.1:54321 web/server01 401 5ms
192.168.1.1:54322 web/server01 403 3ms
192.168.1.1:54323 web/server01 401 4ms
...×8 more
```

**Algorithm:**
1. Filter for 401/403/407 responses
2. Group by source IP
3. Count denials in window
4. If count > threshold (default: 5) → cluster detected

**Signal:**
```python
AnomalySignal(
    kind="proxy_denial_cluster",
    severity=Severity.WARNING,
    representative_events=[5_denials]
)
```

**Interpretation:** Possible brute-force attempt on web service, invalid credentials in config, or blacklist rule triggering.

---

#### Tunnel Anomaly

**Trigger:** VPN/proxy connection errors, e.g.:
- `TLS error`
- `tunnel closed`
- `connection reset`
- `timeout`

**Example (OpenVPN):**
```
user/192.168.1.1:54321 Authenticate/Decrypt packet error: packet HMAC authentication failed
```

**Signal:**
```python
AnomalySignal(
    kind="tunnel_anomaly",
    severity=Severity.WARNING,
    representative_events=[tunnel_error]
)
```

**Interpretation:** Client configuration issue, cert mismatch, or network instability.

---

### Configuration

```yaml
analysis:
  # No specific config (uses fixed thresholds)
```

Thresholds are currently hardcoded:
- Denial cluster: 5+ denials in window
- Tunnel errors: Any error message

### Use Cases

- **API gateway protection:** Detect credential stuffing
- **Load balancer health:** Upstream server failures
- **VPN monitoring:** Client configuration issues

---

## 5. Correlation Engine (`analysis/correlation.py`)

**Goal:** Deduplicate overlapping signals to avoid reporting the same incident multiple times.

### Algorithm

1. **Group signals by time overlap**
   - For each signal, find all others within correlation_gap_seconds
   - Example: 16:45-16:50 signal correlates with 16:46-16:51 signal (120s gap)

2. **Check for relationship**
   - Are signals related? (same source, related kinds, etc.)
   - Example: `error_burst` + `rate_spike` on same source → related

3. **Merge related signals**
   - Keep the earliest signal
   - Extend window to latest signal's end
   - Combine representative events
   - Keep highest severity

4. **Discard duplicates**
   - Remove redundant signals

### Example

```
Input signals:
  A: error_burst, window=16:45-16:50, source=nginx
  B: rate_spike, window=16:46-16:51, source=nginx
  C: oom_event,  window=16:44-16:44, source=kernel

After correlation:
  A+B merged → error_burst, window=16:45-16:51, severity=ERROR
  C standalone → oom_event, window=16:44-16:44, severity=CRITICAL

Output: [merged_A_B, C]
```

### Configuration

```yaml
analysis:
  correlation_gap_seconds: 120    # Max gap for correlation (2 minutes)
```

### Implementation Details

Correlation uses a union-find algorithm to group related signals:

```python
def correlate_signals(
    signals: list[AnomalySignal],
    config: Config,
) -> list[AnomalySignal]:
    # Build graph of related signals
    # Use union-find to group
    # Merge signals in each group
    # Return deduplicated list
```

### Why Correlation Matters

Without correlation:
```
Input log: 1000 events in 5 minutes with 50% errors

Output signals:
  - error_burst: "1000 events in 5 min" (3x baseline)
  - rate_spike: "50% errors in 5 min" (3x baseline)

User sees 2 alerts for the same incident → confusion
```

With correlation:
```
Output signals:
  - error_burst (merged): "1000 events in 5 min with 50% errors"

User sees 1 alert for the underlying issue → clarity
```

---

## Analysis Orchestration (`analysis/engine.py`)

### Main Function

```python
def run_analysis(
    parsed_events: list[ParsedEvent],
    log_path: str,
    parser_format: str,
    config: Config,
    baseline: dict[str, float],
) -> AnalysisResult:
    """Run all analysis engines."""
    
    all_signals = []
    
    # Run each engine
    all_signals.extend(analyze_bursts(parsed_events, config, baseline))
    all_signals.extend(analyze_error_rates(parsed_events, config, baseline))
    all_signals.extend(analyze_anomalies(parsed_events, config))
    all_signals.extend(analyze_proxy_anomalies(parsed_events, config))
    
    # Deduplicate
    all_signals = correlate_signals(all_signals, config)
    
    # Return results
    return AnalysisResult(
        log_path=log_path,
        parser_format=parser_format,
        parsed_count=len(parsed_events),
        skipped_count=...,
        time_range=TimeWindow(...),
        signals=all_signals,
    )
```

### Performance

- **Parsing:** O(n) where n = line count
- **Each engine:** O(n log n) to O(n) depending on algorithm
- **Total:** O(n log n) typical case, dominated by sorting/grouping

### Typical Times

- 10K events: ~50ms
- 100K events: ~500ms
- 1M events: ~5 seconds

---

## Testing Analysis Engines

See `/tests/unit/test_analysis/` for test patterns:

```bash
# Test burst detection
pytest tests/unit/test_analysis/test_burst.py -v

# Test error rate detection
pytest tests/unit/test_analysis/test_error_rate.py -v

# Test all analysis
pytest tests/unit/test_analysis/ -v

# Integration test (full pipeline)
pytest tests/integration/ -v
```

---

## Debugging Analysis

Enable verbose logging to see signal detection:

```bash
logcrux /var/log/syslog --verbose
```

Output includes:
```
DEBUG: Burst analysis: found 2 signals
DEBUG: Error rate analysis: found 1 signal
DEBUG: Anomaly patterns: found 1 oom_event
DEBUG: Proxy analysis: found 0 signals
DEBUG: Correlation: merged 1 signal, removed 0 duplicates
DEBUG: Total signals: 3
```

---

**Last Updated:** July 2026
