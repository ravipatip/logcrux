# Inference System

The inference system uses ONNX-based AI models to classify incidents into 7 categories. This document explains how classification works and how to customize it.

## Overview

### What Inference Does

Given incident messages detected by statistical analysis, the inference system:

1. **Selects representative messages** from anomaly signals
2. **Embeds messages** using a local sentence-embedding model
3. **Classifies** using a 7-way local classification model
4. **Clusters** related messages using cosine similarity
5. **Returns confidence score** for the predicted category

### Architecture

```
AnomalySignal(representative_events=[...])
    ↓
[Extract representative messages]
    ↓
[Embed with local sentence-embedding model]
    ↓
[Classifier: 7-way softmax]
    ↓
[Find max probability]
    ↓
[If confidence >= threshold, return category]
    ↓
[Else return UNKNOWN]
    ↓
InferenceResult(category, confidence)
```

## Models

### 1. Classifier Model

**Type:** Fine-tuned local classification model  
**Task:** 7-way incident classification  
**Input:** Log messages (text)  
**Output:** Softmax probability over 7 categories  
**Model Size:** ~22MB ONNX (INT8-quantized)  
**Latency:** ~50-100ms per incident  

**Categories:**
```python
class IncidentCategory(str, Enum):
    OOM = "oom"
    AUTH_BRUTE_FORCE = "auth_brute_force"
    HTTP_OVERLOAD = "http_overload"
    DISK_FULL = "disk_full"
    SERVICE_CRASH = "service_crash"
    CONFIG_ERROR = "config_error"
    NETWORK_ISSUE = "network_issue"
    UNKNOWN = "unknown"  # Special: below threshold
```

**Training Data:** A curated set of real-world and synthetic log examples, balanced across categories.

### 2. Grouper Model

**Type:** Local sentence-embedding model  
**Task:** Event clustering via embeddings  
**Input:** Log messages (text)  
**Output:** Vector embeddings (384-dim)  
**Model Size:** ~22MB ONNX (INT8-quantized)  
**Latency:** ~10ms per message  

**Usage:** Cluster similar events to show user representative groups:
```
Group 1 (4 events):
  - "Failed password for user admin from 192.168.1.100"
  - "Invalid user admin from 192.168.1.100"

Group 2 (2 events):
  - "Accepted password for root from 192.168.1.100"
```

## Classification Logic

### Representative Messages

Not all events in an anomaly are sent to the classifier. Instead:

1. **Select 2-5 representative events** from each anomaly signal
2. **Prioritize diverse events:** If signal has 100 events, pick ones that cover different message types
3. **Extract message text:** Use `event.message` (cleaned, no raw log cruft)
4. **Pass to classifier:** Feed cleaned messages

**Why:** The model was trained on one message per example. Feeding the entire anomaly message set would:
- Overwhelm the model's context window
- Average out the signal (too many irrelevant messages dilute the classification)
- Not match training distribution

### Confidence Threshold

```python
def classify(messages: list[str], config: Config) -> InferenceResult:
    # Run classifier
    logits = model(messages)
    
    # Convert to probabilities
    softmax = torch.softmax(logits, dim=-1)
    
    # Average across representative messages
    avg_softmax = softmax.mean(dim=0)
    
    # Get max probability and category
    confidence = avg_softmax.max()
    category_idx = avg_softmax.argmax()
    category = CATEGORIES[category_idx]
    
    # Check threshold
    if confidence < config.inference.threshold:
        category = IncidentCategory.UNKNOWN
    
    return InferenceResult(
        category=category,
        confidence=float(confidence),
        ...
    )
```

### Threshold Tuning

**Default:** 0.35 (filters near-random predictions)

**Interpretation:**
- **Random guess (7 categories):** 1/7 ≈ 0.14 (14% confidence)
- **0.14-0.35:** Below threshold, marked UNKNOWN (probably wrong)
- **0.35-0.7:** Moderate confidence (accept but mark WARNING level)
- **0.7-1.0:** High confidence (mark CRITICAL level)

**Tuning:**
```yaml
# Lenient (catch more categories, accept some false positives)
inference:
  threshold: 0.2

# Balanced (default)
inference:
  threshold: 0.35

# Strict (high-confidence only)
inference:
  threshold: 0.6
```

## Graceful Degradation

If ONNX models aren't found, inference is **gracefully disabled:**

1. Check for model files at startup
2. If missing, log warning: "AI inference unavailable: ..."
3. Continue with statistical analysis only
4. Output shows findings based on signal types (no AI category)
5. Summarizer infers category from signal kinds

**When Models Are Missing:**
- Shallow/partial clone that dropped the model files
- Models manually deleted
- `logcrux/inference/models/` directory inaccessible

**User Sees:**
```
Analysis Complete (no ONNX models)

Findings:
• 47 failed SSH attempts from 192.168.1.100
  Detected signal type: auth_failure_cluster

Remediation:
1. Block IP: sudo ufw insert 1 deny from 192.168.1.100
2. Reset compromised passwords

Status: Statistical analysis only (AI inference unavailable)
```

## Category Details

### OOM (Out-of-Memory)

**Triggered by:** Deterministic "killed for OOM" pattern  
**Confidence:** Usually high (pattern match, not AI)  
**Example:** `"Killed process 1234 (java) score 100 or sacrifice child"`  
**Context:** System memory pressure, one process dies  
**Remediation:** Increase memory, optimize app, investigate memory leak

---

### AUTH_BRUTE_FORCE

**Triggered by:** Cluster of failed auth attempts OR AI classifier  
**Confidence:** High if 10+ failed attempts, medium if AI-only  
**Example:** 47 failed SSH logins from same IP  
**Context:** Attack or misconfiguration (wrong password, key)  
**Remediation:** Block IP, reset password, audit other accounts, enable rate limiting

---

### HTTP_OVERLOAD

**Triggered by:** High 5xx error rate OR AI classifier  
**Confidence:** High if correlated with error burst  
**Example:** 100+ HTTP 502/503 errors in 5 minutes  
**Context:** Backend overload, cascading failures, resource exhaustion  
**Remediation:** Scale up, load balance, investigate upstream, check resource limits

---

### DISK_FULL

**Triggered by:** Deterministic "no space" pattern  
**Confidence:** Very high (exact pattern match)  
**Example:** `"write failed: No space left on device"`  
**Context:** Filesystem is at 100% capacity  
**Remediation:** Free space, delete old logs, clean temp files, add disk space

---

### SERVICE_CRASH

**Triggered by:** Deterministic crash pattern OR AI classifier  
**Confidence:** High if "exited with signal" found  
**Example:** `"exited with signal 11 (SIGSEGV)"`  
**Context:** Unexpected process termination  
**Remediation:** Check core dump, review logs, restart service, update app

---

### CONFIG_ERROR

**Triggered by:** AI classifier (pattern-based detection limited)  
**Confidence:** Medium to high  
**Example:** "syntax error at line 5", "invalid option"  
**Context:** Configuration mistake preventing startup or normal operation  
**Remediation:** Validate config file, check syntax, review changes

---

### NETWORK_ISSUE

**Triggered by:** AI classifier (pattern-based detection limited)  
**Confidence:** Medium to high  
**Example:** "Connection reset by peer", "Temporary failure in name resolution"  
**Context:** Network connectivity or DNS problems  
**Remediation:** Check network connectivity, test DNS, review firewall rules

---

### UNKNOWN

**Triggered by:** No clear pattern AND confidence < threshold  
**Confidence:** Low by definition  
**Example:** Unusual error that doesn't fit other categories  
**Context:** Rare or novel incident  
**Remediation:** Manual investigation required

## Signal-Category Mapping

When only statistical signals are available (no AI inference):

| Signal Kind | Inferred Category |
|-------------|-------------------|
| oom_event | OOM |
| auth_failure_cluster | AUTH_BRUTE_FORCE |
| disk_full | DISK_FULL |
| service_crash | SERVICE_CRASH |
| error_burst (high severity) | UNKNOWN |
| rate_spike (with errors) | HTTP_OVERLOAD (if web) or UNKNOWN |
| tunnel_anomaly | NETWORK_ISSUE |
| proxy_denial_cluster | HTTP_OVERLOAD |

## Embedding & Clustering

The grouper model clusters related events via cosine similarity:

```python
def group_events(
    events: list[ParsedEvent],
    model: GrouperModel,
) -> list[list[int]]:
    """
    Group events by message similarity.
    Returns indices of events in each cluster.
    """
    messages = [event.message for event in events]
    
    # Embed each message
    embeddings = model.embed(messages)  # Shape: (N, 384)
    
    # Compute cosine similarity
    similarities = cosine_similarity(embeddings)
    
    # Cluster by similarity >= 0.75
    clusters = []
    used = set()
    
    for i in range(len(messages)):
        if i in used:
            continue
        
        cluster = [i]
        used.add(i)
        
        for j in range(i + 1, len(messages)):
            if j not in used and similarities[i][j] >= 0.75:
                cluster.append(j)
                used.add(j)
        
        clusters.append(cluster)
    
    return clusters
```

**Threshold (0.75):** Empirically chosen to group variations of the same failure while keeping distinct issues separate.

## Using Inference Programmatically

```python
from logcrux.inference.engine import InferenceEngine
from logcrux.models import ParsedEvent

# Initialize
engine = InferenceEngine(config=config)

# Classify
events = [ParsedEvent(...), ...]
result = engine.classify(events)

# Check result
if result is None:
    print("Models unavailable")
else:
    print(f"Category: {result.category}")
    print(f"Confidence: {result.confidence}")
    print(f"Clusters: {result.grouped_event_clusters}")
```

## Model Files

Located in `logcrux/inference/models/` (committed directly, INT8-quantized):

```
logcrux/inference/models/
├── classifier/model.onnx   # 7-way incident classifier (~22MB)
├── grouper/model.onnx      # Sentence embeddings for clustering (~22MB)
└── tokenizer/               # Shared tokenizer
```

**Format:** ONNX (open inference standard)  
**Why ONNX:** Portable, no PyTorch runtime needed, fast inference  
**Implementation:** Uses ONNX Runtime (CPU or GPU)

## Debugging Inference

### Check Models Exist

```bash
ls -lah logcrux/inference/models/
# Should show ~22MB files, not 100-byte stubs
```

### Enable Verbose Logging

```bash
logcrux /var/log/syslog --verbose 2>&1 | grep -i "inference"
```

### Test Classification Programmatically

```python
python
>>> from logcrux.inference.engine import InferenceEngine
>>> from logcrux.config import Config
>>> engine = InferenceEngine(Config())
>>> 
>>> # Test with sample messages
>>> messages = [
...     "Killed process 1234 (java) score 100 or sacrifice child",
...     "Out of memory: Kill process 5678 (python)"
... ]
>>> result = engine.classify(messages)
>>> print(result.category, result.confidence)
```

### Check Softmax Outputs

To see all 7 category probabilities (not just max):

```python
# Modify logcrux/inference/classifier.py temporarily
def classify(...):
    # ... existing code ...
    softmax = torch.softmax(logits, dim=-1)
    
    # Print all probabilities
    for category, prob in zip(CATEGORIES, softmax[0]):
        print(f"{category}: {prob:.3f}")
    
    # ... rest of code ...
```

---

**Last Updated:** July 2026
