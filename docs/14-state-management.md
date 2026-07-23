# State Management

logcrux uses SQLite to track baselines and run history. This document explains the state system and how to manage it.

## Overview

The state system stores two types of information:

1. **Baselines:** Historical event rate averages by log format
2. **Run history:** Results of previous analyses for trend tracking

## Database Location

Default: `~/.local/share/logcrux/state.db`

**Override:**
```yaml
# In config file
state:
  db_path: /var/cache/logcrux/state.db
```

Or via CLI (sets temporary location):
```bash
logcrux /var/log/syslog --no-baseline  # Disable baseline entirely
```

## Database Schema

### baselines Table

Stores event rate baselines per log format.

```sql
CREATE TABLE baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    format TEXT NOT NULL UNIQUE,           -- e.g., "nginx_access", "syslog"
    baseline_rate REAL NOT NULL,           -- Events per minute (average)
    last_updated TIMESTAMP NOT NULL,       -- When baseline was last updated
    sample_count INTEGER DEFAULT 0,        -- How many analyses contributed
);
```

**Example:**
```
format          baseline_rate   last_updated        sample_count
─────────────────────────────────────────────────────────────────
nginx_access    125.5           2026-06-20 16:45    47
syslog          45.2            2026-06-20 15:30    102
postgresql      12.3            2026-06-19 10:00    8
```

### run_history Table

Stores results of each analysis for trend analysis.

```sql
CREATE TABLE run_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL UNIQUE,      -- UUID from IncidentSummary
    log_path TEXT NOT NULL,                -- Analyzed file
    format TEXT NOT NULL,                  -- Detected format
    level TEXT NOT NULL,                   -- CLEAN, INFO, WARNING, CRITICAL
    category TEXT,                         -- IncidentCategory
    confidence REAL,                       -- 0.0-1.0
    parsed_count INTEGER NOT NULL,         -- Lines successfully parsed
    signal_count INTEGER NOT NULL,         -- Anomalies detected
    analyzed_at TIMESTAMP NOT NULL,        -- When analysis ran
    elapsed_seconds REAL,                  -- Analysis duration
);
```

**Example:**
```
analysis_id  log_path          format    level     category          confidence
──────────────────────────────────────────────────────────────────────────────
a1b2c3d4...  /var/log/auth     secure    CRITICAL  auth_brute_force  0.92
e5f6g7h8...  /var/log/syslog   syslog    WARNING   unknown           0.45
```

## Baseline Tracking

### How Baselines Work

Baselines are exponentially smoothed averages of event rates:

```
baseline_new = α × current_rate + (1 - α) × baseline_old
```

Where:
- `α` = `baseline_alpha` config (default: 0.2)
- `current_rate` = Events in current analysis / time range
- `baseline_old` = Previous baseline for this format

### First Analysis

When analyzing a log format for the first time:

1. No baseline exists yet → skip baseline comparison
2. Calculate event rate from current analysis
3. Insert new baseline into database
4. Output notes: "First analysis, establishing baseline"

### Subsequent Analyses

1. Load baseline for format
2. Compare current rate against baseline
3. Flag if current > baseline × spike_factor
4. Update baseline with exponential smoothing
5. Store results in run_history

### Why Exponential Smoothing?

Without smoothing:
```
baseline would jump on every anomaly:
  Normal: 50 events/min
  Anomaly: 500 events/min
  → New baseline becomes 500
  → All future 50 looks like drop (false positive)
```

With smoothing (α=0.2):
```
baseline smoothly adapts:
  baseline_new = 0.2 × 500 + 0.8 × 50 = 140
  → Elevated but not swayed
  Next normal: baseline_new = 0.2 × 50 + 0.8 × 140 = 122
  → Gradually returns to normal
```

This prevents a single anomaly from poisoning future detections.

### Tuning Smoothing Factor

```yaml
state:
  baseline_alpha: 0.2  # Default: 20% weight to current, 80% to history
```

**α = 0.1** (10% current, 90% history):
- Very stable baseline
- Slow to adapt to real changes
- Good for stable systems

**α = 0.2** (20% current, 80% history) [Default]:
- Balanced stability/adaptability
- Good for most cases

**α = 0.5** (50% current, 50% history):
- Responsive to changes
- Higher false positives from anomalies
- Good for variable workloads

## Managing State

### View Baselines

```bash
sqlite3 ~/.local/share/logcrux/state.db
> SELECT format, baseline_rate, sample_count FROM baselines;
```

Output:
```
nginx_access|125.5|47
syslog|45.2|102
postgresql|12.3|8
```

### View Run History

```bash
sqlite3 ~/.local/share/logcrux/state.db
> SELECT log_path, format, level, category, confidence FROM run_history
  ORDER BY analyzed_at DESC
  LIMIT 10;
```

Output:
```
/var/log/auth.log|secure|CRITICAL|auth_brute_force|0.92
/var/log/syslog|syslog|WARNING|unknown|0.45
...
```

### Clear All State

```bash
rm ~/.local/share/logcrux/state.db
# Baselines and history are deleted
# Next analysis will start with no baseline (as if first time)
```

### Clear Specific Format Baseline

```bash
sqlite3 ~/.local/share/logcrux/state.db
> DELETE FROM baselines WHERE format = 'nginx_access';
```

### Backup State

```bash
cp ~/.local/share/logcrux/state.db ~/.local/share/logcrux/state.db.backup
```

### Restore from Backup

```bash
cp ~/.local/share/logcrux/state.db.backup ~/.local/share/logcrux/state.db
```

## Skipping Baseline

To analyze without baseline comparison:

```bash
logcrux /var/log/syslog --no-baseline
```

**Effect:**
- Baseline is NOT loaded from database
- Analysis runs with no historical context
- Anomalies detected only by burst/error_rate thresholds
- Baseline is NOT updated (database unchanged)
- Output shows: "Baseline: N/A (--no-baseline flag)"

**When to Use:**
- First analysis of a new log type (to establish baseline)
- Comparing against system defaults (no historical data relevant)
- Testing analysis thresholds
- When state.db is corrupted or unavailable

## State File Issues

### Issue: Permission Denied

```
Error: Cannot write to ~/.local/share/logcrux/state.db
Permission denied
```

**Solution:**
```bash
# Check ownership
ls -la ~/.local/share/logcrux/state.db

# Fix if owned by root
sudo chown $(whoami) ~/.local/share/logcrux/state.db
chmod 600 ~/.local/share/logcrux/state.db

# Or create parent directory
mkdir -p ~/.local/share/logcrux
touch ~/.local/share/logcrux/state.db
chmod 600 ~/.local/share/logcrux/state.db
```

### Issue: Database Locked

```
Error: Database is locked
```

**Cause:** Another logcrux process is writing to state.db.

**Solution:**
```bash
# Check for running processes
pgrep -f logcrux

# Kill stray process if needed
kill -9 <pid>

# Or use --no-baseline to skip state entirely
logcrux /var/log/syslog --no-baseline
```

### Issue: Corrupted Database

```
Error: Database disk image is malformed
```

**Solution:**
```bash
# Delete and recreate
rm ~/.local/share/logcrux/state.db

# Next analysis will create fresh database
logcrux /var/log/syslog
```

## Querying State

### Count Analyses by Level

```bash
sqlite3 ~/.local/share/logcrux/state.db
> SELECT level, COUNT(*) FROM run_history GROUP BY level;
```

Output:
```
CLEAN|47
CRITICAL|3
WARNING|12
```

### Find Most Common Categories

```bash
> SELECT category, COUNT(*) FROM run_history
  WHERE category != 'unknown'
  GROUP BY category
  ORDER BY COUNT(*) DESC;
```

Output:
```
auth_brute_force|5
service_crash|3
http_overload|2
```

### Trend: Is System Improving?

```bash
> SELECT 
    DATE(analyzed_at) as date,
    COUNT(*) as incidents,
    SUM(CASE WHEN level = 'CRITICAL' THEN 1 ELSE 0 END) as critical
  FROM run_history
  GROUP BY date
  ORDER BY date DESC
  LIMIT 30;
```

Output:
```
2026-06-20|5|1
2026-06-19|8|2
2026-06-18|12|4
...
```

## State in Tests

For testing, use a temporary database:

```python
# conftest.py
@pytest.fixture
def temp_db(tmp_path):
    """Temporary state database for testing."""
    db_path = tmp_path / "test.db"
    return Database(str(db_path))

def test_baseline_update(temp_db):
    """Test baseline tracking."""
    baseline = get_baseline(temp_db, "syslog")
    assert baseline is None  # First time
    
    upsert_baseline(temp_db, "syslog", 100.0)
    baseline = get_baseline(temp_db, "syslog")
    assert baseline == 100.0
```

Or skip state entirely in tests:

```bash
# Run tests without state
logcrux /var/log/syslog --no-baseline
```

## Performance Impact

State operations are fast:

- **Load baseline:** ~1ms (single SELECT)
- **Update baseline:** ~5ms (INSERT/UPDATE)
- **Store run history:** ~2ms (single INSERT)
- **Total state overhead:** <10ms per analysis

For large-scale deployments, state access is negligible overhead.

---

**Last Updated:** July 2026
