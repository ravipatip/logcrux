# Exit Codes & Integration

logcrux uses exit codes to indicate analysis results, enabling integration with automation and monitoring systems.

## Exit Codes

| Code | Meaning | Usage |
|------|---------|-------|
| **0** | CLEAN — No anomalies detected | Success, safe to proceed |
| **3** | WARNING/INFO — Incidents found | Alert, but not critical |
| **4** | CRITICAL — Severe incidents found | Escalate, take action |
| **1** | ERROR — Analysis failed | Investigate failure |

## Code Semantics

### 0 — Clean

```bash
$ logcrux /var/log/syslog
$ echo $?
0
```

**Meaning:** No anomalies detected, system is healthy.

**Output:**
```
╭─ logcrux ──────────────────────────────────╮
│ CLEAN: No anomalies detected               │
├──────────────────────────────────────────────┤
│ Parsed: 1234 events                        │
│ Analysis took 0.45s                        │
╰──────────────────────────────────────────────╯
```

### 3 — Warning/Info

```bash
$ logcrux /var/log/syslog
$ echo $?
3
```

**Meaning:** Some incidents detected (INFO or WARNING level), but not critical.

**Output:**
```
╭─ logcrux ──────────────────────────────────────────────────────╮
│ WARNING: Elevated error rate                                   │
├──────────────────────────────────────────────────────────────────┤
│ Findings:                                                       │
│ • 2.5x normal error rate in past hour                          │
│   Investigate application logs for root cause                  │
│                                                                │
│ Category: Unknown (0.42 confidence)                            │
├──────────────────────────────────────────────────────────────────┤
│ Parsed: 5678 events | Analysis took 1.2s                      │
╰──────────────────────────────────────────────────────────────────╯
```

### 4 — Critical

```bash
$ logcrux /var/log/auth.log
$ echo $?
4
```

**Meaning:** Severe incidents detected (CRITICAL level), immediate action needed.

**Output:**
```
╭─ logcrux ──────────────────────────────────────────────────────╮
│ CRITICAL: Successful brute-force attack on SSH                 │
├──────────────────────────────────────────────────────────────────┤
│ Findings:                                                       │
│ • 47 failed SSH attempts from 192.168.1.100                    │
│ • 1 successful login post-attack (account compromised)         │
│                                                                │
│ Category: Auth Brute Force (0.92 confidence)                   │
│                                                                │
│ Remediation:                                                   │
│ 1. Block IP: sudo ufw insert 1 deny from 192.168.1.100        │
│ 2. Reset passwords for compromised accounts                    │
│ 3. Audit login activity: grep "Accepted" /var/log/auth.log    │
├──────────────────────────────────────────────────────────────────┤
│ Parsed: 427 events | Analysis took 0.23s                      │
╰──────────────────────────────────────────────────────────────────╯
```

### 1 — Error

```bash
$ logcrux /nonexistent/path.log
$ echo $?
1
```

**Meaning:** Analysis failed to run (file not found, permission denied, etc.).

**Output:**
```
Error: Cannot read log file
  /nonexistent/path.log: No such file or directory
```

## Integration Examples

### Conditional Action

```bash
#!/bin/bash

logcrux /var/log/syslog
case $? in
    0)
        echo "All clear"
        ;;
    3)
        echo "Minor issues detected"
        # Send info alert
        ;;
    4)
        echo "CRITICAL incident"
        # Send critical alert, page oncall
        ;;
    1)
        echo "Analysis failed"
        # Debug and retry
        ;;
esac
```

### Continuous Monitoring

```bash
#!/bin/bash

while true; do
    logcrux /var/log/syslog --last 30m
    case $? in
        0)
            sleep 300  # Check again in 5 minutes
            ;;
        3)
            # Log alert but continue
            echo "WARNING" | logger -t logcrux
            sleep 60
            ;;
        4)
            # Escalate immediately
            echo "CRITICAL" | logger -t logcrux
            # Send alert, page team
            break
            ;;
    esac
done
```

### Automated Remediation

```bash
#!/bin/bash

RESULT=$(logcrux /var/log/auth.log --json)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 4 ]; then
    # Parse JSON to get incident details
    CATEGORY=$(echo $RESULT | jq -r '.category')
    
    if [ "$CATEGORY" = "auth_brute_force" ]; then
        # Extract attacker IP from findings
        IP=$(echo $RESULT | jq -r '.findings[0].headline' | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        # Block immediately
        sudo ufw insert 1 deny from $IP
        
        # Alert team
        echo "Blocked attacker: $IP" | mail -s "SSH Attack" security@example.com
    fi
fi
```

### Monitoring Stack Integration

#### Prometheus

```bash
#!/bin/bash
# Exporter script for Prometheus

RESULT=$(logcrux /var/log/syslog --json)
EXIT_CODE=$?
LEVEL=$(echo $RESULT | jq -r '.level')
CONFIDENCE=$(echo $RESULT | jq -r '.confidence')

echo "logcrux_exit_code $EXIT_CODE"
echo "logcrux_level{level=\"$LEVEL\"} 1"
echo "logcrux_confidence $CONFIDENCE"
```

#### Nagios/Icinga

```bash
#!/bin/bash
# Nagios plugin

logcrux /var/log/syslog > /tmp/logcrux_output.txt
EXIT=$?

case $EXIT in
    0)
        echo "OK: No incidents detected"
        exit 0
        ;;
    3)
        echo "WARNING: $(grep 'Findings' /tmp/logcrux_output.txt | head -1)"
        exit 1
        ;;
    4)
        echo "CRITICAL: $(grep 'Findings' /tmp/logcrux_output.txt | head -1)"
        exit 2
        ;;
    *)
        echo "UNKNOWN: Analysis failed"
        exit 3
        ;;
esac
```

#### Splunk

```bash
#!/bin/bash
# Splunk HEC ingestion

EVENT=$(logcrux /var/log/syslog --json)
EXIT_CODE=$?

curl -k https://splunk.example.com:8088/services/collector \
  -H "Authorization: Splunk <token>" \
  -d "{\"event\": $EVENT, \"exit_code\": $EXIT_CODE}"
```

### Cron Monitoring

```bash
# crontab
0 * * * * /usr/local/bin/logcrux /var/log/syslog --last 1h || \
  echo "logcrux analysis failed with code $?" | \
  mail -s "Log analysis failed" admin@example.com
```

If exit code is non-zero, the `||` clause executes and sends an alert.

### Systemd Service Alert

```ini
# /etc/systemd/system/logcrux-monitor.service

[Unit]
Description=logcrux Log Analysis Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/logcrux-monitor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
#!/usr/bin/env bash
# /usr/local/bin/logcrux-monitor.sh

while true; do
    logcrux /var/log/syslog --last 1h > /tmp/logcrux.out
    CODE=$?
    
    if [ $CODE -eq 4 ]; then
        systemctl start alert-critical.service
    elif [ $CODE -eq 3 ]; then
        systemctl start alert-warning.service
    fi
    
    sleep 300
done
```

## JSON Output Integration

For programmatic integration, use `--json` flag:

```bash
logcrux /var/log/syslog --json > /tmp/result.json
```

**Output:**
```json
{
  "analysis_id": "a1b2c3d4-e5f6-4789-0123-456789abcdef",
  "level": "CRITICAL",
  "title": "Successful brute-force attack on SSH",
  "findings": [
    {
      "headline": "47 failed SSH login attempts from 192.168.1.100 in 5-min window",
      "detail": "Baseline: 2 attempts/hour. This is 5.6x higher."
    }
  ],
  "confidence": 0.92,
  "category": "auth_brute_force",
  "remediation": "1. Block attacker IP...",
  "log_path": "/var/log/auth.log",
  "parser_format": "secure",
  "analyzed_at": "2026-06-20T16:45:22",
  "parsed_count": 427,
  "skipped_count": 0,
  "elapsed_seconds": 0.23
}
```

### Parsing JSON in Scripts

**Python:**
```python
import json
import subprocess

result = subprocess.run(
    ["logcrux", "/var/log/syslog", "--json"],
    capture_output=True,
    text=True
)

if result.returncode == 4:  # CRITICAL
    data = json.loads(result.stdout)
    print(f"Incident: {data['title']}")
    print(f"Category: {data['category']}")
    print(f"Confidence: {data['confidence']:.1%}")
```

**jq (command-line):**
```bash
logcrux /var/log/syslog --json | jq '.title, .category, .confidence'

# Output:
# "Successful brute-force attack on SSH"
# "auth_brute_force"
# 0.92
```

## Testing Integration

```bash
#!/bin/bash
# test-integration.sh

# Test CLEAN
echo "Test 1: CLEAN"
logcrux --version > /dev/null
[ $? -eq 0 ] && echo "✓ PASS" || echo "✗ FAIL"

# Test CRITICAL (use real log with known attack)
echo "Test 2: CRITICAL"
logcrux tests/fixtures/auth_brute_force.log
[ $? -eq 4 ] && echo "✓ PASS" || echo "✗ FAIL"

# Test ERROR
echo "Test 3: ERROR"
logcrux /nonexistent/log.txt 2>&1 | grep -q "Error"
[ $? -eq 1 ] && echo "✓ PASS" || echo "✗ FAIL"

# Test JSON output
echo "Test 4: JSON"
OUTPUT=$(logcrux tests/fixtures/auth_brute_force.log --json)
echo $OUTPUT | jq '.category' | grep -q "auth_brute_force"
[ $? -eq 0 ] && echo "✓ PASS" || echo "✗ FAIL"
```

## Important Notes

### Exit Code Stability

Exit codes are **stable and documented.** Don't rely on detailed error messages (which may change), but always rely on numeric codes:

```bash
# ✓ Good: Relies on code
if [ $? -eq 4 ]; then alert(); fi

# ✗ Bad: Relies on error message text
if grep -q "critical" stderr; then alert(); fi
```

### One Analysis Per Invocation

Each `logcrux` invocation is independent:

```bash
# Each run is separate, baselines may update between runs
logcrux /var/log/syslog --last 1h
logcrux /var/log/syslog --last 1h  # May have different baseline
```

For consistent monitoring, use the same timeframe consistently.

---

**Last Updated:** July 2026
