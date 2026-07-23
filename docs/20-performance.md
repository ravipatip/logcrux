# Performance Optimization

This document provides guidance on optimizing logcrux performance for large-scale log analysis.

## Performance Profile

Peak resident memory is roughly a **~190 MB fixed baseline** (Python, ONNX
Runtime, and the two loaded models) **plus ~2.5 KB per parsed event**, since
all events are held in memory for the analysis passes. Times below exclude
the ~1.2 s one-time model load.

| Log Size | Events | Time (after startup) | Peak RSS |
|----------|--------|----------------------|----------|
| Small | 1K | ~0.02s | ~190MB |
| Medium | 10K | ~0.1s | ~215MB |
| Large | 100K | ~1.1s | ~440MB |
| XL | 1M | ~11s | ~2.7GB (projected) |
| XXL | 10M+ | ~110s+ | ~25GB+ (projected) |

Measured with logcrux 0.9.0 on an Apple M-series laptop against an nginx
access log at 1K and 101K events; the XL/XXL rows extrapolate the per-event
cost and have not been run. Times are hardware-dependent; the memory shape
is structural.

The practical consequence: `security.max_file_size_mb` (default 2048) is a
*file size* limit, not a memory limit. A multi-GB log will exhaust RAM well
before it hits that ceiling. Use `--last`, or pre-filter the stream, for
anything past ~1M events.

## Bottlenecks

### 1. File I/O (10% of time)

Reading from disk or stdin.

**Optimization:**
- Already single-threaded pass → can't parallelize
- SSD vs HDD doesn't matter much (log analysis is CPU-bound)

### 2. Parsing (30% of time)

Each line matched against the parser registry (short-circuits on first match), then format-specific parsing.

**Optimization:**
- Parser detection is once at start (not per-line)
- Format-specific parsing is O(1) per line
- Mostly regex matching (well-optimized in Python)
- Can't do much here without rewriting parsers

### 3. Analysis (40% of time)

Burst, error rate, anomaly, proxy, correlation engines.

**Optimization:**
- Sorting/grouping: O(n log n)
- Correlation: Union-find → O(n α(n)) ≈ O(n)
- Anomaly pattern matching: Substring search (linear)
- Can reduce window size or disable engines if needed

### 4. Inference (20% of time)

AI model inference for classification.

**Optimization:**
- ONNX inference is fast (~50-100ms per incident)
- Only runs if signals detected
- Can disable with `inference.enabled: false`

## Optimization Techniques

### 1. Analyze Recent Logs Only

```bash
# Last 1 hour instead of all
logcrux /var/log/syslog --last 1h

# Reduces events to process
# Baseline still applies (more meaningful comparison)
```

**Impact:** 24x faster for daily logs

**Trade-off:** May miss slow-moving anomalies

### 2. Pipe Large Files

```bash
# Read from pipe (streaming) instead of file
tail -n 100000 /var/log/syslog | logcrux

# Reduces memory: tail streams, logcrux processes
```

**Impact:** 10x less memory

**Trade-off:** Can't use file path for detection hints

### 3. Disable Inference

```bash
# Disable AI classification
inference:
  enabled: false
```

Or CLI:
```bash
# Modify config and rerun
```

**Impact:** 20% faster overall

**Trade-off:** No AI categorization, only statistical signals

### 4. Increase Analysis Window

```yaml
analysis:
  window_size_minutes: 10  # Default 5
```

**Impact:** Less granular but faster analysis

**Trade-off:** Miss shorter bursts

### 5. Disable Correlation

If you only care about detecting anomalies (not deduplication):

```python
# In analysis/engine.py, comment out correlation
# all_signals = correlate_signals(all_signals, config)  # → all_signals
```

**Impact:** ~5% faster

**Trade-off:** Possible duplicate alerts

### 6. Skip Baseline Comparison

```bash
logcrux /var/log/syslog --no-baseline
```

**Impact:** Slightly faster (no DB query/update)

**Trade-off:** Less context for anomaly detection

## Scaling Recommendations

### <100K Events (< 1 second expected)

No optimization needed.

```bash
logcrux /var/log/syslog
```

### 100K - 1M Events (1-5 seconds expected)

Use `--last` to reduce scope:

```bash
# Only analyze last hour
logcrux /var/log/syslog --last 1h

# Or tail large file
tail -n 500000 /var/log/syslog | logcrux
```

### 1M - 10M Events (5-50 seconds expected)

Combine techniques:

```bash
# Last 30 minutes + pipe
tail -n 1000000 /var/log/syslog | logcrux

# Disable inference
# Edit config to disable inference
```

### 10M+ Events (50+ seconds expected)

Split analysis:

```bash
# Analyze hourly instead of daily
for h in {0..23}; do
  logcrux /var/log/syslog --last 1h --json >> /tmp/daily-summary.jsonl
done
```

Or use external tools for pre-filtering:

```bash
# Grep before piping to logcrux
grep -i "error" /var/log/syslog | logcrux
```

## Profiling

### Profile Runtime

```bash
python -m cProfile -s cumtime logcrux /var/log/syslog > profile.txt
head -50 profile.txt
```

Shows which functions consume most time.

### Profile Memory

```bash
pip install memory-profiler

python -m memory_profiler logcrux /var/log/syslog
```

Shows memory usage over time.

### Benchmark

```bash
time logcrux /var/log/syslog
# Shows real / user / sys time
```

Compare before/after optimization.

## Parallelization

logcrux is currently single-threaded. Parallelization opportunities:

### Per-Format Analysis (Possible)

```
If analyzing multiple formats in one log:
  Parallel: Parse + analyze each format separately
  (Requires restructuring how events are grouped)
```

**Effort:** High
**Benefit:** Limited (most logs are single format)

### Per-Engine Analysis (Possible)

```
Run analysis engines in parallel:
  Burst + Error Rate + Anomaly + Proxy concurrently
  (Each engine reads full event list independently)
```

**Effort:** Medium
**Benefit:** 4x speedup on quad-core (diminishing with I/O bottleneck)

### Inference Batching (Possible)

```
Batch classify multiple incidents in one model call
  (Currently: One incident → one inference call)
```

**Effort:** Medium
**Benefit:** 10-50x speedup for multi-incident logs

Currently not implemented. Would be good optimization target.

## Memory Optimization

### Current Memory Usage

logcrux loads entire event list in memory:

```python
parsed_events = [parser.parse_line(...) for ...]  # All in RAM
```

**Alternative (streaming):** Process in sliding windows

```python
def analyze_streaming(file_path, window_size=10000):
    for batch in read_batches(file_path, window_size):
        analyze_batch(batch)
        yield results
```

**Benefit:** Constant memory instead of O(n)

**Cost:** More complex, can't detect cross-window anomalies

## Database Performance

State DB (SQLite) is very fast:

- Load baseline: <1ms
- Insert baseline: <5ms
- Query run history: <10ms

Not a bottleneck. Only optimize if analyzing 100s of different formats.

## Network Performance

logcrux is local-only. No network dependency.

**If integrating with remote systems:**

```bash
# Send JSON to remote service
logcrux /var/log/syslog --json | \
  curl -X POST -d @- http://remote:8000/incidents
```

Network time dominates (100+ ms). Batch if analyzing frequently.

## Recommended Settings by Scale

### Development (Single Server)

```yaml
analysis:
  window_size_minutes: 5
  burst_multiplier: 3.0
  spike_factor: 3.0

inference:
  enabled: true
  threshold: 0.35

state:
  baseline_alpha: 0.2
```

### Small Production (1-100K events/day)

```yaml
analysis:
  window_size_minutes: 10
  burst_multiplier: 3.0

inference:
  enabled: true

state:
  baseline_alpha: 0.2
```

Add `--last 1h` to hourly cron jobs.

### Large Production (1M+ events/day)

```yaml
analysis:
  window_size_minutes: 15
  burst_multiplier: 4.0
  spike_factor: 4.0

inference:
  enabled: false  # Disable for speed

state:
  baseline_alpha: 0.3  # Adapt faster
```

Use `--last 30m` to limit scope. Consider splitting analysis by log format.

## Future Optimizations

- [ ] Parallel analysis engines
- [ ] Streaming event processing
- [ ] Batch inference
- [ ] Cache baselines in memory
- [ ] Incremental analysis (only new events)
- [ ] GPU-accelerated inference

---

**Last Updated:** July 2026
