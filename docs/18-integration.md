# Integration

logcrux can be integrated into monitoring, alerting, and log management systems. This document shows integration patterns.

## Library Usage

Use logcrux programmatically from Python:

```python
from pathlib import Path
from logcrux.parsers.registry import detect_parser
from logcrux.analysis.engine import run_analysis
from logcrux.summarizer.engine import summarize
from logcrux.inference.engine import InferenceEngine
from logcrux.config import Config
from logcrux.state.db import Database
from logcrux.state.baseline import get_baseline, upsert_baseline

# Load config
config = Config()

# Read log file
log_path = Path("/var/log/syslog")
log_text = log_path.read_text()
lines = log_text.split("\n")

# Detect parser
parser = detect_parser(log_path, lines[:100])
print(f"Detected: {parser.FORMAT_NAME}")

# Parse all lines
parsed_events = [
    parser.parse_line(line, i)
    for i, line in enumerate(lines)
    if parser.parse_line(line, i) is not None
]

# Load baseline
db = Database(config.state.db_path)
baseline = get_baseline(db, parser.FORMAT_NAME) or {}

# Run analysis
analysis_result = run_analysis(
    parsed_events,
    str(log_path),
    parser.FORMAT_NAME,
    config,
    baseline,
)

# Update baseline
if parsed_events:
    event_rate = len(parsed_events) / 10  # Per minute (assuming 10 min window)
    upsert_baseline(db, parser.FORMAT_NAME, event_rate)

# Run inference
inference_engine = InferenceEngine(config)
inference_result = inference_engine.classify(
    [e.message for e in analysis_result.signals[0].representative_events]
    if analysis_result.signals else []
)

# Summarize
summary = summarize(analysis_result, inference_result, config)

# Use result
print(f"Level: {summary.level}")
print(f"Title: {summary.title}")
print(f"Category: {summary.category}")
print(f"Confidence: {summary.confidence:.2%}")
```

## Command-Line Integration

### Bash Scripting

```bash
#!/bin/bash

logcrux /var/log/syslog --last 1h
EXIT_CODE=$?

case $EXIT_CODE in
    0)
        echo "All clear"
        ;;
    3)
        echo "Minor incidents"
        # Send info alert
        ;;
    4)
        echo "CRITICAL"
        # Page oncall
        ;;
    1)
        echo "Analysis failed"
        ;;
esac

exit $EXIT_CODE
```

### Cron Monitoring

```bash
# /etc/cron.d/logcrux-monitor
0 * * * * root /usr/local/bin/logcrux /var/log/syslog --last 1h > /var/log/logcrux-hourly.log 2>&1

# Alert on failure
0 * * * * root /usr/local/bin/logcrux /var/log/syslog --last 1h || echo "logcrux failed with code $?" | mail -s "logcrux failed" ops@example.com
```

### Systemd Timer

```ini
# /etc/systemd/system/logcrux-monitor.service
[Unit]
Description=logcrux Log Analysis
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/logcrux /var/log/syslog --last 1h
StandardOutput=journal

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/logcrux-monitor.timer
[Unit]
Description=Run logcrux hourly

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Unit=logcrux-monitor.service

[Install]
WantedBy=timers.target
```

Enable:
```bash
systemctl enable --now logcrux-monitor.timer
systemctl status logcrux-monitor.timer
```

## Monitoring Stack Integration

### Prometheus

```python
#!/usr/bin/env python3
# /usr/local/bin/logcrux-exporter

import json
import subprocess

result = subprocess.run(
    ["logcrux", "/var/log/syslog", "--json"],
    capture_output=True,
    text=True
)

data = json.loads(result.stdout)

# Prometheus metrics
print(f"logcrux_exit_code {result.returncode}")
print(f'logcrux_level{{level="{data["level"]}"}} 1')
print(f"logcrux_confidence {data['confidence']}")
print(f"logcrux_parsed_count {data['parsed_count']}")
print(f"logcrux_elapsed_seconds {data['elapsed_seconds']}")
```

Add to scrape config:
```yaml
scrape_configs:
  - job_name: logcrux
    static_configs:
      - targets: ['localhost:8000']
```

### Grafana Dashboard

Query:
```
rate(logcrux_exit_code[5m])
```

Shows:
- Exit code 0: CLEAN
- Exit code 3: WARNING
- Exit code 4: CRITICAL
- Exit code 1: ERROR

### Splunk

```bash
#!/bin/bash
# Forward logcrux output to Splunk HEC

RESULT=$(logcrux /var/log/syslog --json)

curl -k https://splunk.example.com:8088/services/collector \
  -H "Authorization: Splunk $(cat /etc/logcrux/splunk-hec-token)" \
  -d "{\"event\": $RESULT, \"sourcetype\": \"logcrux\"}"
```

### ELK Stack

```bash
#!/bin/bash
# Send logcrux to Elasticsearch

RESULT=$(logcrux /var/log/syslog --json)
TIMESTAMP=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

curl -X POST "elasticsearch:9200/logcrux/_doc" \
  -H 'Content-Type: application/json' \
  -d "$(echo "$RESULT" | jq --arg ts "$TIMESTAMP" '.timestamp = $ts')"
```

### CloudWatch (AWS)

```bash
#!/bin/bash
# Send to CloudWatch Logs

RESULT=$(logcrux /var/log/syslog --json)

aws logs put-log-events \
  --log-group-name /var/log/syslog \
  --log-stream-name logcrux \
  --log-events "timestamp=$(date +%s000),message=$RESULT"
```

## Alerting Integration

### PagerDuty

```bash
#!/bin/bash

RESULT=$(logcrux /var/log/syslog --json)
EXIT=$?

if [ $EXIT -eq 4 ]; then
    TITLE=$(echo $RESULT | jq -r '.title')
    REMEDIATION=$(echo $RESULT | jq -r '.remediation')
    
    curl -X POST https://events.pagerduty.com/v2/enqueue \
      -H 'Content-Type: application/json' \
      -d "{
        \"routing_key\": \"$(cat /etc/logcrux/pd-routing-key)\",
        \"event_action\": \"trigger\",
        \"dedup_key\": \"logcrux-$(date +%s)\",
        \"payload\": {
          \"summary\": \"$TITLE\",
          \"severity\": \"critical\",
          \"source\": \"logcrux\",
          \"custom_details\": {
            \"remediation\": \"$REMEDIATION\"
          }
        }
      }"
fi
```

### Slack

```bash
#!/bin/bash

RESULT=$(logcrux /var/log/syslog --json)
EXIT=$?

if [ $EXIT -eq 4 ]; then
    TITLE=$(echo $RESULT | jq -r '.title')
    REMEDIATION=$(echo $RESULT | jq -r '.remediation')
    
    curl -X POST $SLACK_WEBHOOK \
      -H 'Content-Type: application/json' \
      -d "{
        \"text\": \"⚠️ CRITICAL\",
        \"blocks\": [
          {
            \"type\": \"section\",
            \"text\": {
              \"type\": \"mrkdwn\",
              \"text\": \"*$TITLE*\n\n\`\`\`$REMEDIATION\`\`\`\"
            }
          }
        ]
      }"
fi
```

## Webhook Integration

For custom integrations:

```bash
#!/bin/bash

RESULT=$(logcrux /var/log/syslog --json)
EXIT=$?

curl -X POST https://your-service.example.com/webhook \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $(cat /etc/logcrux/webhook-token)" \
  -d "$RESULT"
```

Webhook receives:
```json
{
  "analysis_id": "...",
  "level": "CRITICAL",
  "title": "...",
  "category": "...",
  "confidence": 0.92,
  "remediation": "...",
  "parsed_count": 427,
  "elapsed_seconds": 0.23
}
```

## Log Aggregation Integration

### Forward to Central Syslog

```bash
#!/bin/bash

RESULT=$(logcrux /var/log/syslog --json)
EXIT=$?

logger -t logcrux -p user.warning "$(echo "$RESULT" | jq -c .)"
```

Central syslog server receives structured log from logcrux.

### Send to Log Service

```bash
#!/bin/bash

RESULT=$(logcrux /var/log/syslog --json)

# Datadog
curl -X POST "https://http-intake.logs.datadoghq.com/v1/input" \
  -H "DD-API-KEY: $(cat /etc/logcrux/datadog-api-key)" \
  -d "$RESULT"

# Or Loggly
curl -X POST "https://logs-01.loggly.com/inputs/$(cat /etc/logcrux/loggly-token)/tag/logcrux/" \
  -d "$RESULT"
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Log Analysis

on:
  schedule:
    - cron: '0 * * * *'  # Hourly

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install logcrux
        run: pip install logcrux
      
      - name: Analyze logs
        run: logcrux /var/log/syslog --json > /tmp/result.json
      
      - name: Check for incidents
        run: |
          LEVEL=$(jq -r '.level' /tmp/result.json)
          if [ "$LEVEL" = "CRITICAL" ]; then
            echo "::error::Critical incident detected"
            exit 1
          fi
```

### GitLab CI

```yaml
analyze_logs:
  image: ubuntu:22.04
  schedule:
    - cron: '0 * * * *'
  script:
    - pip install logcrux
    - logcrux /var/log/syslog --json > result.json
    - |
      if grep -q '"level": "CRITICAL"' result.json; then
        echo "Critical incident"
        exit 1
      fi
```

---

**Last Updated:** July 2026
