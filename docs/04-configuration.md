# Configuration

logcrux can be configured via YAML files or command-line arguments. YAML provides more detailed control, while CLI arguments override YAML settings.

## Configuration File Locations

logcrux searches for configuration files in this order:

1. `--config <path>` (CLI option)
2. `~/.config/logcrux/logcrux.yaml` (user home)
3. `/etc/logcrux/logcrux.yaml` (system-wide)
4. Hardcoded defaults (if no files found)

If multiple files exist, the first one found is used (no merging).

## Configuration Format

Configuration is YAML with three main sections: `analysis`, `inference`, and `state`.

```yaml
analysis:
  window_size_minutes: 5          # Time window for burst/rate analysis
  burst_multiplier: 3.0            # Event threshold = baseline × multiplier
  auth_failure_threshold: 10       # Count for auth_failure_cluster signal
  correlation_gap_seconds: 120     # Max gap between correlated signals
  spike_factor: 3.0                # Error rate spike = baseline × factor

inference:
  enabled: true                    # Enable AI classification
  threshold: 0.35                  # Min softmax confidence for category

state:
  db_path: ~/.local/share/logcrux/state.db
  baseline_alpha: 0.2              # Exponential smoothing factor

security:
  allowed_log_paths: []            # Empty = no restriction
  max_file_size_mb: 2048           # File size limit

output:
  color: true                      # Terminal colors
  show_remediation: true           # Include remediation in output
```

## Configuration Sections

### analysis

Controls statistical anomaly detection.

```yaml
analysis:
  window_size_minutes: 5
```
**Default:** `5`  
**Range:** 1-60  
**Meaning:** Events are grouped into 5-minute windows for burst/rate analysis. Smaller windows detect faster anomalies but may have false positives. Larger windows smooth out noise.

```yaml
  burst_multiplier: 3.0
```
**Default:** `3.0`  
**Range:** 1.0-10.0  
**Meaning:** A burst is triggered when event frequency exceeds baseline × multiplier. A value of 3.0 means 3x normal is anomalous. Lower values catch more anomalies (more false positives). Higher values are stricter.

```yaml
  auth_failure_threshold: 10
```
**Default:** `10`  
**Range:** 3-100  
**Meaning:** Minimum number of failed authentication attempts in a window to trigger `auth_failure_cluster` signal. Lower thresholds catch smaller attacks. Higher thresholds reduce false positives.

```yaml
  correlation_gap_seconds: 120
```
**Default:** `120`  
**Range:** 30-3600  
**Meaning:** If two anomaly signals occur within 120 seconds of each other and relate to the same issue, they're merged into one. This prevents reporting the same incident twice.

```yaml
  spike_factor: 3.0
```
**Default:** `3.0`  
**Range:** 1.0-10.0  
**Meaning:** Error rate spike is triggered when error proportion exceeds baseline × factor. Similar to `burst_multiplier` but focuses on error-severity events.

### inference

Controls AI-powered classification.

```yaml
inference:
  enabled: true
```
**Default:** `true`  
**Meaning:** If true, use ONNX models for incident classification. If false or models unavailable, skip AI inference (analysis continues).

```yaml
  threshold: 0.35
```
**Default:** `0.35`  
**Range:** 0.0-1.0  
**Meaning:** Minimum softmax confidence for the AI classifier to report a category. Below this, category is marked UNKNOWN.

**Rationale:**
- The classifier is 7-way (7 incident categories)
- Random guess = 1/7 ≈ 0.14 confidence
- 0.35 filters out near-random predictions
- Tuning guidance:
  - **0.2**: Lenient (report more categories, risk false positives)
  - **0.35**: Default (balance precision/recall)
  - **0.5+**: Strict (high-confidence predictions only)

### state

Controls persistence and baseline tracking.

```yaml
state:
  db_path: ~/.local/share/logcrux/state.db
```
**Default:** `~/.local/share/logcrux/state.db`  
**Meaning:** Path to SQLite database for baselines and run history. Use `--no-baseline` to skip baseline usage without deleting the file.

```yaml
  baseline_alpha: 0.2
```
**Default:** `0.2`  
**Range:** 0.0-1.0  
**Meaning:** Exponential smoothing factor for updating baselines.

**Formula:**
```
baseline_new = α × current_rate + (1 - α) × baseline_old
```

**Examples:**
- **α = 0.1:** History has 90% weight (slow adaptation, stable but lag)
- **α = 0.2:** History has 80% weight (default, balanced)
- **α = 0.5:** Equal weight (fast adaptation, more volatile)

Lower α prevents baselines from being skewed by a single anomaly.

### security

Controls access policies.

```yaml
security:
  allowed_log_paths: []
```
**Default:** `[]` (empty list = no restriction)  
**Meaning:** If set, logcrux can only analyze files under these paths. Examples:
```yaml
allowed_log_paths:
  - /var/log
  - /opt/app/logs
  - /home/*/logs
```

**Rationale:** Prevents analyzing arbitrary system files (e.g., `/etc/shadow`).

```yaml
  max_file_size_mb: 2048
```
**Default:** `2048` (2GB)  
**Range:** 1-10000  
**Meaning:** Maximum log file size to analyze. Files larger than this are rejected.

### output

Controls output rendering.

```yaml
output:
  color: true
```
**Default:** `true`  
**Meaning:** If true, use Rich terminal colors. If false, plain text.

```yaml
  show_remediation: true
```
**Default:** `true`  
**Meaning:** If true, include remediation steps in terminal output. JSON output always includes remediation regardless.

## Command-Line Argument Priority

CLI arguments override YAML settings. For example:

```bash
# YAML has threshold: 0.5
logcrux /var/log/syslog --threshold 0.3  # Uses 0.3 instead
```

### CLI Options

```
--last <duration>              Only analyze last N time units (30s, 10m, 2h, 1d)
--format <format>              Override auto-detection (e.g., nginx, mysql)
--threshold <float>            Override inference threshold (0.0-1.0)
--no-baseline                  Skip baseline comparison (don't read/update DB)
--json                         Output JSON instead of Rich terminal
--config <path>               Use custom config file
--verbose                      Enable debug logging
--version                      Show version
```

## Example Configurations

### Lenient (Catch More Issues)

```yaml
analysis:
  window_size_minutes: 3           # Smaller windows
  burst_multiplier: 2.0            # Lower threshold
  spike_factor: 2.0

inference:
  threshold: 0.2                   # More categories reported
```

### Strict (High Precision)

```yaml
analysis:
  window_size_minutes: 10          # Larger windows
  burst_multiplier: 5.0            # Higher threshold
  spike_factor: 5.0

inference:
  threshold: 0.6                   # Only high-confidence reports
```

### Minimal State (No Baseline)

```yaml
state:
  db_path: /tmp/logcrux-temp.db    # Temporary location
  baseline_alpha: 0.1              # Slow baseline updates

# Or use CLI:
logcrux /var/log/syslog --no-baseline
```

### Development/Testing

```yaml
output:
  color: false                     # For logging/testing
  show_remediation: false          # Concise output

inference:
  enabled: false                   # Skip AI for faster iteration

state:
  db_path: /tmp/logcrux-test.db    # Separate test DB
```

## Environment Variable Overrides

Currently unsupported. Use `--config` instead:

```bash
logcrux /var/log/syslog --config ~/.config/logcrux/custom.yaml
```

## Default Configuration (Hardcoded)

If no YAML file exists, logcrux uses these defaults:

```python
analysis=AnalysisConfig(
    window_size_minutes=5,
    burst_multiplier=3.0,
    auth_failure_threshold=10,
    correlation_gap_seconds=120,
    spike_factor=3.0,
),
inference=InferenceConfig(
    enabled=True,
    threshold=0.35,
),
state=StateConfig(
    db_path="~/.local/share/logcrux/state.db",
    baseline_alpha=0.2,
),
security=SecurityConfig(
    allowed_log_paths=[],
    max_file_size_mb=2048,
),
output=OutputConfig(
    color=True,
    show_remediation=True,
),
```

## Configuration Validation

logcrux validates configuration on startup:

- **window_size_minutes:** Must be 1-60
- **burst_multiplier:** Must be 1.0-10.0
- **spike_factor:** Must be 1.0-10.0
- **auth_failure_threshold:** Must be 3-100
- **correlation_gap_seconds:** Must be 30-3600
- **threshold:** Must be 0.0-1.0
- **max_file_size_mb:** Must be 1-10000
- **db_path:** Must be writable directory (parent)
- **allowed_log_paths:** Must be absolute paths or globs

**Error Example:**
```
Error: Invalid configuration
  window_size_minutes must be 1-60, got 100
```

## Troubleshooting Configuration Issues

### Config File Not Found

```bash
# Check where logcrux looks
logcrux --verbose 2>&1 | grep -i config

# Explicitly set config
logcrux /var/log/syslog --config /etc/logcrux/logcrux.yaml
```

### Invalid YAML Syntax

logcrux reports line/column:
```
Error: Invalid YAML in ~/.config/logcrux/logcrux.yaml
  Line 5: Missing value for key 'window_size_minutes'
```

### Threshold Too High (No Results)

If threshold is 0.8 and model outputs 0.7:
```
Output: "Category: UNKNOWN (below threshold)"
```

Adjust:
```yaml
inference:
  threshold: 0.6
```

### Baseline Not Updating

If baseline file is read-only:
```bash
# Check permissions
ls -la ~/.local/share/logcrux/state.db

# Fix ownership
chown $(whoami) ~/.local/share/logcrux/state.db
chmod 600 ~/.local/share/logcrux/state.db

# Or skip baseline entirely
logcrux /var/log/syslog --no-baseline
```

---

**Last Updated:** July 2026
