# Anomaly Detection

logcrux detects 9 types of anomalies through pattern matching, statistical analysis, and AI classification. This document describes each detection method.

## Overview

```
Input: Parsed Events
  ↓
Burst Analysis          → error_burst signal
Error Rate Analysis     → rate_spike signal
Anomaly Patterns        → oom_event, disk_full, auth_failure_cluster, service_crash
Proxy Analysis          → proxy_denial_cluster, tunnel_anomaly
  ↓
Correlation            → Deduplicate overlapping signals
  ↓
Output: Deduplicated AnomalySignal list
```

## Signal Types

### 1. error_burst

**What:** Sudden spike in high-frequency events (any severity level)

**Detection:** Event count in window > baseline × burst_multiplier (default 3.0)

**Example:**
```
Normal: 20 events per 5-min window
Burst: 180 events in 5-min window → 9x normal → ALERT
```

**Indicates:**
- Service becoming very verbose
- Rapid error loops
- System under stress

**Severity:** ERROR (for errors), WARNING (for warnings/info)

See `docs/08-analysis-engines.md` § Burst Analysis for implementation.

---

### 2. rate_spike

**What:** Increased proportion of error-severity events

**Detection:** Error% in window > baseline% × spike_factor (default 3.0)

**Example:**
```
Normal error rate: 5%
Spike: 25% errors in 5-min window → 5x baseline → ALERT
```

**Indicates:**
- Application experiencing failures
- Database query errors
- Upstream service issues

**Severity:** ERROR

See `docs/08-analysis-engines.md` § Error Rate Analysis.

---

### 3. auth_failure_cluster

**What:** Multiple failed authentication attempts from same source

**Detection:** Count of failed auth in window > auth_failure_threshold (default 10)

**Example:**
```
Failed logins from 192.168.1.100:
  17:00 - Failed password for admin
  17:01 - Failed password for root
  17:02 - Failed password for test
  ... (10+ total in 5 minutes)
→ ALERT
```

**Indicates:**
- Brute-force attack attempt
- Misconfigured credentials
- Compromised account under attack

**Severity:** CRITICAL

---

### 4. oom_event

**What:** Process killed by kernel for out-of-memory

**Detection:** Substring match "killed process" + "out of memory"

**Example:**
```
Killed process 12345 (java) score 100 or sacrifice child
```

**Indicates:**
- System memory exhaustion
- Memory leak in application
- Resource limits too low

**Severity:** CRITICAL

---

### 5. disk_full

**What:** Filesystem capacity exceeded

**Detection:** Substring match "no space left on device"

**Example:**
```
write error: No space left on device
```

**Indicates:**
- Filesystem at 100% capacity
- Log file runaway
- Temporary files accumulating

**Severity:** CRITICAL

---

### 6. service_crash

**What:** Process/daemon unexpected termination

**Detection:** Substring match for crash signals:
- "exited with signal"
- "segmentation fault"
- "bus error"
- "aborted"

**Example:**
```
[error] 12345#0: *9999 segmentation fault at ...
nginx: master process exited with code 1
```

**Indicates:**
- Code bug causing crash
- Memory corruption
- Invalid operation

**Severity:** ERROR

---

### 7. tunnel_anomaly

**What:** VPN/proxy connection error

**Detection:** Substring match for tunnel failures:
- "TLS error"
- "tunnel closed"
- "connection reset"
- "timeout"

**Example:**
```
Authenticate/Decrypt packet error: packet HMAC authentication failed
```

**Indicates:**
- Client config mismatch
- Certificate issue
- Network instability

**Severity:** WARNING

---

### 8. proxy_denial_cluster

**What:** Multiple HTTP 4xx (denial) responses from same source

**Detection:** Count of 401/403/407 from same IP > 5 in window

**Example:**
```
192.168.1.100 - - [20/Jun/2026:16:45:00] "GET / HTTP/1.1" 401
192.168.1.100 - - [20/Jun/2026:16:45:01] "GET / HTTP/1.1" 403
... (5+ denials in short time)
```

**Indicates:**
- Credential stuffing attempt
- Invalid API key usage
- Authorization failure pattern

**Severity:** WARNING

---

### 9. unknown

**What:** Generic anomaly that doesn't fit other categories

**Detection:** Residual signal after correlation

**Indicates:**
- Unusual pattern not matching known types
- Novel incident type

**Severity:** WARNING

---

## Pattern Matching vs. Threshold

### Threshold-Based (Burst, Rate, Proxy)

Detects based on statistical deviation:
- Compare current against baseline
- Flag if exceeds multiplier threshold
- More prone to false positives if thresholds too low

**Advantage:** Adapts to system workload  
**Disadvantage:** Requires baseline history

### Pattern-Based (OOM, Disk Full, Auth, Crash)

Detects based on exact strings/substrings:
- OOM: "killed process" + "out of memory"
- Disk: "no space left"
- Auth: Failed login count
- Crash: Signal/fault messages

**Advantage:** Precise, no false positives  
**Disadvantage:** Doesn't catch variations

### Hybrid (Auth Failure)

Combines pattern + threshold:
- Pattern: Identify failed auth attempts
- Threshold: Count cluster if > 10 in window

---

## Severity Assignment

Each signal has a severity indicating urgency:

| Severity | Meaning | Example |
|----------|---------|---------|
| CRITICAL | Immediate action needed | OOM kill, brute-force with success |
| ERROR | Alert warranted | Service crash, disk full |
| WARNING | Monitor closely | Denial cluster, tunnel anomaly |

The **highest severity** signal determines the overall incident level.

---

## Configuration

```yaml
analysis:
  window_size_minutes: 5              # Window for burst/rate analysis
  burst_multiplier: 3.0               # Alert if > baseline × this
  spike_factor: 3.0                   # Alert if error% > baseline% × this
  auth_failure_threshold: 10          # Min failed attempts to trigger
  correlation_gap_seconds: 120        # Max gap for signal correlation
```

---

## Testing Anomaly Detection

```bash
# Test with real anomalies
logcrux tests/fixtures/auth_brute_force.log  # Should detect auth_failure_cluster
logcrux tests/fixtures/oom_kill.log          # Should detect oom_event

# With verbose logging
logcrux /var/log/syslog --verbose 2>&1 | grep -i signal
```

## Next Steps

- See `docs/08-analysis-engines.md` for implementation details
- See `docs/04-configuration.md` for threshold tuning
- See `docs/21-troubleshooting.md` for false positives/negatives

---

**Last Updated:** July 2026
