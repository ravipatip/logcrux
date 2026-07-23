# Output Rendering

logcrux renders results as rich terminal output (default) or JSON (for automation). This document explains output formats and customization.

## Terminal Output

Default output uses the Rich library for formatted, colorized terminal display.

### Example CLEAN Output

```
╭─ logcrux / 2026-06-20 16:45:22 ─────────────────────────────────────────────╮
│ CLEAN: No anomalies detected                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ Log File: /var/log/syslog                                                   │
│ Format: syslog                                                              │
│ Time Range: 2026-06-20 15:45:00 to 16:45:22 (1h)                           │
│ Parsed: 5678 events                                                         │
│ Analysis took 0.45s                                                         │
╰─────────────────────────────────────────────────────────────────────────────╯
```

### Example WARNING Output

```
╭─ logcrux / 2026-06-20 16:45:22 ─────────────────────────────────────────────╮
│ WARNING: Elevated error rate                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ Log File: /var/log/syslog                                                   │
│ Format: syslog                                                              │
│ Time Range: 2026-06-20 15:45:00 to 16:45:22 (1h)                           │
│ Parsed: 5678 events                                                         │
│                                                                              │
│ Findings                                                                     │
│ ────────                                                                     │
│ • 2.5x normal error rate in past hour                                       │
│   Baseline: 45 events/min, Current: 112 events/min                          │
│   Investigate application logs for root cause                               │
│                                                                              │
│ Category: Unknown (0.42 confidence)                                         │
│                                                                              │
│ Remediation                                                                  │
│ ───────────                                                                  │
│ 1. Check application logs: tail -100 /var/log/myapp.log                     │
│ 2. Monitor system resources: top, free, df                                  │
│ 3. Review recent changes: git log, deployment status                        │
│                                                                              │
│ Analysis took 1.2s                                                          │
╰─────────────────────────────────────────────────────────────────────────────╯
```

### Example CRITICAL Output

```
╭─ logcrux / 2026-06-20 16:45:22 ─────────────────────────────────────────────╮
│ CRITICAL: Successful brute-force attack on SSH                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ Log File: /var/log/auth.log                                                │
│ Format: secure (SSH)                                                        │
│ Time Range: 2026-06-20 15:45:00 to 16:45:22 (1h)                           │
│ Parsed: 427 events                                                          │
│                                                                              │
│ Findings                                                                     │
│ ────────                                                                     │
│ • 47 failed SSH login attempts from 192.168.1.100 in 5-min window           │
│   Baseline: 2 attempts/hour. This is 5.6x higher.                          │
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
│ 2. Reset passwords for compromised accounts (root, admin, test)            │
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
│ Analysis took 0.23s                                                         │
╰─────────────────────────────────────────────────────────────────────────────╯
```

## JSON Output

For programmatic use, output JSON with `--json` flag:

```bash
logcrux /var/log/syslog --json > result.json
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
      "detail": "Baseline: 2 attempts/hour. This is 5.6x higher. Targeted users: root, admin, test (common defaults)."
    },
    {
      "headline": "1 successful login post-attack",
      "detail": "At 16:44:12 from 192.168.1.100. Indicates account compromise."
    }
  ],
  "confidence": 0.92,
  "category": "auth_brute_force",
  "remediation": "1. Block IP: sudo ufw insert 1 deny from 192.168.1.100\n2. Reset passwords...",
  "log_path": "/var/log/auth.log",
  "parser_format": "secure",
  "analyzed_at": "2026-06-20T16:45:22",
  "parsed_count": 427,
  "skipped_count": 0,
  "elapsed_seconds": 0.23
}
```

## Customizing Output

### Disable Colors

```yaml
output:
  color: false
```

Or temporarily:
```bash
logcrux /var/log/syslog --no-color  # (if option implemented)
```

### Hide Remediation

```yaml
output:
  show_remediation: false
```

Useful for:
- Automated alerts (don't need remediation steps)
- Compact output
- Integration with external remediation systems

## Output Configuration

```yaml
output:
  color: true                  # Enable terminal colors
  show_remediation: true       # Include remediation steps
  # (future: verbosity, format_preset, etc.)
```

## Integration with Tools

### JSON for Alerting

```python
import json
import subprocess

result = subprocess.run(
    ["logcrux", "/var/log/syslog", "--json"],
    capture_output=True,
    text=True
)

data = json.loads(result.stdout)
if data["level"] == "CRITICAL":
    send_alert(data["title"])
    page_oncall()
```

### Piping to grep/jq

```bash
# Extract just the title
logcrux /var/log/syslog --json | jq -r '.title'

# Check if critical
logcrux /var/log/syslog --json | jq '.level' | grep -q CRITICAL

# Extract findings
logcrux /var/log/syslog --json | jq '.findings[].headline'
```

### Saving for Analysis

```bash
# Run and save output
logcrux /var/log/syslog > /tmp/analysis.txt

# Save JSON for later processing
logcrux /var/log/syslog --json > /tmp/result.json

# Compare multiple runs
diff <(logcrux /var/log/syslog --json) <(logcrux /var/log/syslog --json)
```

## Field Reference

### IncidentSummary Fields

| Field | Type | Description |
|-------|------|-------------|
| `analysis_id` | UUID | Unique ID for this analysis |
| `level` | "CLEAN" \| "INFO" \| "WARNING" \| "CRITICAL" | Severity |
| `title` | string | Incident summary |
| `findings` | list | Detailed findings |
| `confidence` | float | 0.0-1.0, AI classification confidence |
| `category` | string | Incident type (7 categories) |
| `remediation` | string \| null | Steps to fix |
| `log_path` | string | Analyzed file |
| `parser_format` | string | Detected format |
| `analyzed_at` | ISO 8601 datetime | When analysis ran |
| `parsed_count` | integer | Lines successfully parsed |
| `skipped_count` | integer | Unparseable lines |
| `elapsed_seconds` | float | Analysis duration |

### Finding Fields

| Field | Type | Description |
|-------|------|-------------|
| `headline` | string | Brief summary |
| `detail` | string \| null | Detailed explanation |

## Terminal Output Customization

Rich library provides extensive customization. See `logcrux/output/renderer.py` for:
- Panel styling (colors, borders)
- Table formatting
- Header/footer styling
- Markdown rendering

To customize, edit `render_summary()` and related functions.

---

**Last Updated:** July 2026
