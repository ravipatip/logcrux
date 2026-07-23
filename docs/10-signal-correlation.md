# Signal Correlation

Signal correlation deduplicates overlapping anomaly signals to avoid reporting the same incident multiple times.

## Why Correlation Matters

Without correlation, a single incident triggers multiple signals:

```
Incident: Service crashing in loop
  ↓
Signals detected:
  • error_burst: 500 errors in 5 min (10x baseline)
  • rate_spike: 50% errors (3x baseline)
  • service_crash: Process killed signal
  ↓
Without correlation: User sees 3 separate alerts
With correlation: User sees 1 combined alert
```

## Algorithm

### Phase 1: Group by Time

Find signals that overlap in time:

```
Signal A: 16:45-16:50
Signal B: 16:46-16:51   ← overlaps with A
Signal C: 17:00-17:05   ← doesn't overlap

Groups: [A, B], [C]
```

### Phase 2: Check Relationships

Within each time group, check if signals are related:

```python
def are_related(signal_a, signal_b):
    # Same source? (same log format)
    if signal_a.source != signal_b.source:
        return False
    
    # Related kinds? (e.g., burst + rate_spike on same events)
    if are_compatible_kinds(signal_a.kind, signal_b.kind):
        return True
    
    return False
```

### Phase 3: Merge

Merge related signals:

```python
merged = AnomalySignal(
    kind="error_burst",  # Keep the more specific kind
    window=TimeWindow(
        start=min(a.start, b.start),
        end=max(a.end, b.end),
    ),
    event_count=a.event_count + b.event_count,
    severity=max(a.severity, b.severity),  # Take highest
    representative_events=[...a.events, ...b.events]
)
```

## Configuration

```yaml
analysis:
  correlation_gap_seconds: 120  # Max gap between signals to correlate
```

**Default (120s):** Signals within 2 minutes are considered related.

**Adjust:**
- **Shorter (30s):** Stricter correlation, more separate alerts
- **Longer (600s):** Looser correlation, fewer but broader alerts

## Compatible Signal Kinds

Signals are merged if they:
1. Occur in same time window (± correlation_gap_seconds)
2. Affect same source/format
3. Are compatible kinds:

| Kinds | Compatible? | Reason |
|-------|-----------|--------|
| error_burst + rate_spike | ✓ | Same underlying issue (errors) |
| error_burst + auth_failure_cluster | ✗ | Different sources |
| service_crash + error_burst | ✓ | Crash causes error burst |
| oom_event + service_crash | ✓ | OOM kills service |
| disk_full + auth_failure | ✗ | Different issues |

## Example: Correlated Incident

### Before Correlation

```
Detected signals:
  1. error_burst (window 16:45-16:50, 500 errors)
  2. rate_spike (window 16:46-16:51, 45% error rate)
  3. service_crash (window 16:50, nginx crashed)
```

### After Correlation

```
Merged into single signal:
  kind: service_crash  (most specific)
  window: 16:45-16:51  (combined)
  event_count: 500
  severity: CRITICAL   (max of all)
  representative_events: [all from 1, 2, 3]
```

## Edge Cases

### Signals with No Baseline

```
New format, no baseline → can't calculate rate spike
  • error_burst: Still detected (absolute frequency)
  • rate_spike: Skipped (need baseline)
  
No correlation: Both signals kept
```

### Partial Overlap

```
Signal A: 16:45-16:50
Signal B: 16:54-16:59   ← 4-min gap, outside 120s correlation window

If gap > correlation_gap_seconds: Keep separate
```

### Same Events, Different Windows

```
Window 1: 16:45-16:50, 100 events
Window 2: 16:50-16:55, 120 events
Combined: 16:45-16:55, 220 events
```

## Implementation

See `logcrux/analysis/correlation.py`:

```python
def correlate_signals(
    signals: list[AnomalySignal],
    config: Config,
) -> list[AnomalySignal]:
    """
    Merge overlapping signals related to the same issue.
    """
    if not signals:
        return []
    
    # Build time-overlap groups
    groups = build_time_groups(signals, config.analysis.correlation_gap_seconds)
    
    # Merge signals within each group
    merged = []
    for group in groups:
        if len(group) == 1:
            merged.append(group[0])
        else:
            merged.append(merge_signals(group))
    
    return merged
```

## Performance

Correlation is O(n log n) where n = number of signals.

Typically:
- 1-5 signals: <1ms
- 100 signals: <5ms

(Signals are small; most time spent in previous analysis phases)

---

**Last Updated:** July 2026
