# Baseline Tracking

Baselines track historical event rates to provide context for anomaly detection. This document explains how baselines work and how to manage them.

## What Is a Baseline?

A baseline is the **average event rate for a log format**, computed from historical analyses.

```
Format: nginx_access
Baseline: 125.5 events/minute

Meaning: Historically, nginx logs average 125.5 events per minute.
On a new analysis, if we see 500 events/min, that's 4x baseline → spike.
```

## Exponential Smoothing

Baselines are updated using **exponential smoothing**:

```
baseline_new = α × current_rate + (1 - α) × baseline_old
```

Where:
- `α` = smoothing factor (default 0.2, range 0.0-1.0)
- `current_rate` = events/minute in current analysis
- `baseline_old` = previous baseline

### Why Exponential Smoothing?

Without smoothing, a single spike poisons future baselines:

```
Normal rate: 100 events/min
Spike: 1000 events/min
  Without smoothing: baseline becomes 1000 (stuck high)
  With smoothing (α=0.2): baseline = 0.2×1000 + 0.8×100 = 280 (elevated but recovers)
Next normal run (100 events/min):
  baseline = 0.2×100 + 0.8×280 = 244
  Next: baseline = 0.2×100 + 0.8×244 = 215
  ... gradually returns to 100
```

## Tuning Smoothing Factor

### α = 0.1 (10% current, 90% history)

```
Very stable baseline
Slow to adapt to real changes
Good for: Steady-state systems
Bad for: Systems with legitimate load changes
```

### α = 0.2 (20% current, 80% history) [Default]

```
Balanced stability and adaptability
Handles gradual load changes
Good for: Most production systems
```

### α = 0.5 (50% current, 50% history)

```
Responsive to changes
More sensitive to anomalies
Good for: Highly variable systems (CI/CD, batch jobs)
Bad for: Systems prone to spurious alarms
```

### α = 0.9 (90% current, 10% history)

```
Baseline tracks current data very closely
Essentially baseline = current_rate
Not recommended: Each analysis overrides history
```

**Configure:**
```yaml
state:
  baseline_alpha: 0.2  # Adjust as needed
```

## Baseline Lifecycle

### Initial Analysis

```
Format: syslog (first time)
  ↓
Baseline loaded: None (not in DB yet)
  ↓
Analysis runs: 450 events in 10 minutes = 45 events/min
  ↓
Baseline inserted: 45.0 events/min
  ↓
Output: "First analysis, establishing baseline"
```

### Subsequent Analyses

```
Baseline loaded: 45.0 events/min
  ↓
Analysis runs: 500 events in 10 minutes = 50 events/min
  ↓
Baseline updated: 0.2 × 50 + 0.8 × 45 = 46.0
  ↓
Comparison: 50 vs baseline 45 (1.1x) → Normal
```

### Anomalous Analysis

```
Baseline loaded: 45.0 events/min
  ↓
Analysis runs: 2000 events in 10 minutes = 200 events/min
  ↓
Comparison: 200 vs baseline 45 (4.4x) → ALERT (exceeds burst_multiplier 3.0)
  ↓
Baseline updated: 0.2 × 200 + 0.8 × 45 = 76.0
  (elevated but doesn't spike to 200)
  ↓
Next normal analysis: 50 events/min
  Comparison: 50 vs baseline 76 (0.66x) → Normal
  Update: 0.2 × 50 + 0.8 × 76 = 70.8
  (gradually returns toward true baseline)
```

## Baseline Storage

**Location:** SQLite database at `~/.local/share/logcrux/state.db`

**Query:**
```bash
sqlite3 ~/.local/share/logcrux/state.db
> SELECT format, baseline_rate, sample_count, last_updated FROM baselines;
```

**Example Output:**
```
format         baseline_rate  sample_count  last_updated
───────────────────────────────────────────────────────────
nginx_access   125.5          47            2026-06-20 16:45:22
syslog         45.2           102           2026-06-20 15:30:11
postgresql     12.3           8             2026-06-19 10:00:00
```

## Skipping Baseline

### Disable Baseline Comparison

```bash
logcrux /var/log/syslog --no-baseline
```

**Effect:**
- Baseline NOT loaded from database
- Analysis uses only burst/rate thresholds (no context)
- Baseline NOT updated
- Database unchanged

**When to use:**
- First analysis of a new log type (to establish baseline without context)
- Anomaly detection testing
- System doesn't have normal baseline (e.g., new server)

## Resetting Baselines

### Clear Specific Format

```bash
sqlite3 ~/.local/share/logcrux/state.db
> DELETE FROM baselines WHERE format = 'nginx_access';
```

**Effect:** Next nginx analysis starts with no baseline.

### Clear All Baselines

```bash
rm ~/.local/share/logcrux/state.db
```

**Effect:** All baselines and run history deleted. Next analysis creates fresh database.

### Reset to Different Value

```bash
sqlite3 ~/.local/share/logcrux/state.db
> UPDATE baselines SET baseline_rate = 50.0 WHERE format = 'syslog';
```

**Useful for:** Manual tuning if baseline is incorrect.

## Impact on Anomaly Detection

### No Baseline (--no-baseline)

```
Burst multiplier still applies, but against what baseline?
  → Uses average of current analysis instead
  → Less effective for real anomalies
```

### Stale Baseline

```
If system load changed permanently:
  Old baseline: 100 events/min
  New reality: 500 events/min (normal for new workload)
  Result: Every analysis flags spike → alert fatigue
  
Solution: Reset baseline and let it learn new normal
```

### Just Right

```
Baseline tracks true average
Anomalies detected reliably
No alert fatigue from baseline drift
```

## Best Practices

1. **Let baseline stabilize:** 24+ hours of normal operation before expecting good detections

2. **Monitor baseline drift:** Check if baseline is growing/shrinking over time
   ```bash
   sqlite3 ~/.local/share/logcrux/state.db
   > SELECT format, baseline_rate FROM baselines ORDER BY last_updated;
   ```

3. **Reset after major changes:** If system workload changes significantly
   ```bash
   rm ~/.local/share/logcrux/state.db
   # Next analysis starts fresh
   ```

4. **Tune smoothing factor:** For your system type
   - Steady: α = 0.1
   - Variable: α = 0.3-0.4
   - Erratic: α = 0.5

## Troubleshooting

### Issue: Baseline Too High

**Symptom:** Real anomalies not detected (baseline exceeds multiplier)

**Cause:** Baseline learned from noisy/anomalous data

**Solution:**
```bash
# Reset baseline
sqlite3 ~/.local/share/logcrux/state.db
> DELETE FROM baselines WHERE format = 'syslog';

# Or lower smoothing to adapt faster
state:
  baseline_alpha: 0.3
```

### Issue: Baseline Too Low

**Symptom:** False alarms on normal activity

**Cause:** Baseline established during quiet period

**Solution:**
```bash
# Let baseline learn normal workload (24h)
# Or manually set reasonable value
sqlite3 ~/.local/share/logcrux/state.db
> UPDATE baselines SET baseline_rate = 150.0 WHERE format = 'syslog';
```

### Issue: Baseline Not Updating

**Symptom:** Baseline unchanged across multiple analyses

**Cause:** `--no-baseline` flag or state.db not writable

**Solution:**
```bash
# Don't use --no-baseline for production
logcrux /var/log/syslog  # Without flag

# Check permissions
ls -la ~/.local/share/logcrux/state.db
chmod 600 ~/.local/share/logcrux/state.db
```

---

**Last Updated:** July 2026
