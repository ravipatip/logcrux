# logcrux Documentation

Welcome to the **logcrux** documentation. This folder contains comprehensive guides covering all aspects of logcrux—an intelligent, fully local Linux log analyzer powered by AI.

## Quick Navigation

### Getting Started
- **[Overview](./01-overview.md)** — What logcrux is, how it works at a high level, and why you'd use it

### Architecture & Design
- **[Architecture](./02-architecture.md)** — Detailed backend design, component interactions, and data flow
- **[Data Models](./03-data-models.md)** — All core data structures and enums
- **[Configuration](./04-configuration.md)** — How to configure logcrux via YAML

### Log Parsers
- **[Parser System](./05-parser-system.md)** — How the parser detection and registration works
- **[Supported Log Types](./06-supported-log-types.md)** — Complete list of all 209 log format parsers with examples
- **[Adding New Parsers](./07-adding-parsers.md)** — Guide for implementing custom log parsers

### Analysis & Detection
- **[Analysis Engines](./08-analysis-engines.md)** — Detailed breakdown of all 5 analysis modules
- **[Anomaly Detection](./09-anomaly-detection.md)** — How anomalies are identified and classified
- **[Signal Correlation](./10-signal-correlation.md)** — How overlapping signals are deduplicated

### AI & Classification
- **[Inference System](./11-inference-system.md)** — ONNX-based AI classification
- **[Model Training](./12-model-training.md)** — How models are trained and updated
- **[Categorization](./13-categorization.md)** — 7 incident categories and how they're determined

### State & Persistence
- **[State Management](./14-state-management.md)** — SQLite database, baselines, and run history
- **[Baseline Tracking](./15-baseline-tracking.md)** — Exponential smoothing and event rate baselines

### Output & Integration
- **[Output Rendering](./16-output-rendering.md)** — Terminal output, JSON export, and formatting
- **[Exit Codes](./17-exit-codes.md)** — What return codes mean for automation
- **[REST API & Integration](./18-integration.md)** — Programmatic usage and library integration

### Development
- **[Development Guide](./19-development.md)** — Setup, testing, and debugging
- **[Performance Tuning](./20-performance.md)** — Optimization tips for large logs
- **[Troubleshooting](./21-troubleshooting.md)** — Common issues and solutions
- **[Contributing](./22-contributing.md)** — How to contribute code and improvements

## Project Overview

**logcrux** is a command-line tool that analyzes Linux system logs to detect anomalies, security incidents, and system failures without requiring external APIs or cloud connectivity. It combines:

- **Statistical analysis** for error bursts, rate spikes, and specific patterns (OOM, disk full, auth failures)
- **AI classification** using a local classification model to categorize incidents (7 categories)
- **Local state tracking** with SQLite baselines for context-aware anomaly detection
- **Rich terminal output** with findings, confidence scores, and remediation guidance

### Key Stats
- **209 log format parsers** covering system/auth, web servers, databases, cloud-native, SIEM, observability, and more
- **5 analysis engines** for burst, rate, anomaly, proxy, and correlation detection
- **89% test coverage** (1050 tests)
- **~18,600 LOC** (source) + ~8,000 LOC (tests)
- **Python 3.11+** with Pydantic, Typer, Rich, ONNX Runtime

## Quick Start

```bash
# Analyze a log file
logcrux /var/log/syslog

# Analyze with a time window
logcrux /var/log/syslog --last 1h

# Override auto-detection
logcrux /var/log/syslog --format nginx

# Output as JSON
logcrux /var/log/syslog --json

# Adjust AI confidence threshold
logcrux /var/log/syslog --threshold 0.5
```

## Directory Structure

```
docs/
├── README.md                          (This file)
├── 01-overview.md                     Overview & motivation
├── 02-architecture.md                 System design
├── 03-data-models.md                  Core data structures
├── 04-configuration.md                Configuration system
├── 05-parser-system.md                Parser framework
├── 06-supported-log-types.md          All 209 parsers listed
├── 07-adding-parsers.md               Custom parser guide
├── 08-analysis-engines.md             Analysis modules
├── 09-anomaly-detection.md            Anomaly identification
├── 10-signal-correlation.md           Signal deduplication
├── 11-inference-system.md             AI inference
├── 12-model-training.md               Model training pipeline
├── 13-categorization.md               7 incident categories
├── 14-state-management.md             SQLite persistence
├── 15-baseline-tracking.md            Baseline computation
├── 16-output-rendering.md             Output formatting
├── 17-exit-codes.md                   Exit code semantics
├── 18-integration.md                  Library usage
├── 19-development.md                  Development setup
├── 20-performance.md                  Optimization guide
├── 21-troubleshooting.md              Problem solving
└── 22-contributing.md                 Contributing guide
```

## Contributing

See [Contributing](./22-contributing.md) for guidelines on submitting PRs, reporting issues, and improving documentation.

## License

logcrux is licensed under the Apache License 2.0. See the LICENSE file in the repository root for full terms.

---

**Last Updated:** July 2026  
**Maintainer:** Ravipati
