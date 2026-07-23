# Parser System

logcrux's parser system automatically detects log formats and extracts structured data from unstructured text. This document explains how parsers work and how they're detected.

## Overview

### What Parsers Do

Each parser:
1. **Detects** if it can handle a given log file
2. **Parses** each line into structured `ParsedEvent` objects
3. **Extracts** format-specific fields (IP, status code, user, etc.)

### Parser Registry

All parsers are registered in `logcrux/parsers/registry.py`:

```python
_PARSERS: list[type[LogParser]] = [
    KubernetesParser,
    DockerParser,
    JournaldParser,
    NginxErrorParser,
    ApacheErrorParser,
    # ... 200 more parsers
    SyslogParser,
    GenericParser,  # Last resort fallback
]
```

**Order matters.** Parsers are tried in order, and the first that returns `True` from `can_parse()` is used.

## Parser Interface

All parsers inherit from `LogParser`:

```python
from logcrux.parsers.base import LogParser
from logcrux.models import ParsedEvent, Severity

class MyFormatParser(LogParser):
    FORMAT_NAME = "myformat"  # Unique identifier
    
    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        """Return True if this parser recognizes the format."""
        # Check path and/or sample content
        return should_use_this_parser
    
    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        """Parse one line into a ParsedEvent or None if unparseable."""
        # Extract timestamp, severity, message, etc.
        return ParsedEvent(
            timestamp=...,
            severity=...,
            source=...,
            message=...,
            raw=line,
            line_number=line_number,
            extra={}  # Format-specific fields
        )
```

## Detection Strategy

### Path-Based Detection

The simplest detection uses file path:

```python
@classmethod
def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
    if path is None:
        return False
    
    path_str = str(path).lower()
    return "kubernetes" in path_str and "/pods/" in path_str
```

**Advantages:** Fast, no need to read file  
**Disadvantages:** Assumes naming conventions

### Sample-Based Detection

Read first N lines and check content:

```python
@classmethod
def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
    if not sample_lines:
        return False
    
    # Check for distinctive pattern
    for line in sample_lines:
        if '"$date":' in line and '"s":"E"' in line:
            return True  # Looks like MongoDB JSON
    return False
```

**Advantages:** Reliable, format-agnostic  
**Disadvantages:** Need to read file, slower

### Hybrid Detection

Combine both:

```python
@classmethod
def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
    # Path hint
    if path and "nginx" in str(path).lower() and "error" in str(path).lower():
        return True
    
    # Sample confirmation
    if sample_lines and any("[error]" in line for line in sample_lines):
        return True
    
    return False
```

## Detection Precision

**Critical:** Prevent false positives where one parser incorrectly claims a file intended for another.

### Good Detectors

```python
# Kubernetes: Very specific path pattern
"kubernetes" in path and "/pods/" in path and "/containers/" in path

# MongoDB JSON: Very specific field pattern
'"$date"' in sample and '"s":"E"' in sample  # S = severity

# HAProxy: Very specific log format prefix
"haproxy[" in line
```

### Bad Detectors (Too Broad)

```python
# ❌ BAD: Nginx detector that matches any HTTP access log
"GET" in line or "POST" in line
# (This would match Apache, Squid, HAProxy, etc.)

# ❌ BAD: JSON detector
"{" in line
# (This would match MongoDB, Elasticsearch, Docker, etc.)

# ❌ BAD: Syslog detector without specificity
":" in line
# (This matches almost every log format)
```

### Detection Order

Parsers are ordered by specificity:

1. **Path-specific** (nearly 100% precision)
   - Kubernetes, Docker, journald
   - These match only their intended format

2. **Format-specific** (high precision)
   - Nginx error vs. access (different error tag format)
   - Apache error vs. access (different timestamp format)
   - HAProxy (specific "haproxy[" prefix)

3. **Syslog-tagged** (medium precision)
   - Must use `syslog_tag_dominant()` helper to avoid false positives
   - Example: sudo parser checks if "sudo" tag appears in most lines

4. **Structured logs** (low order dependency)
   - MongoDB, Elasticsearch, Kafka have distinctive JSON shapes
   - Order among them doesn't matter

5. **System catch-alls** (last resort)
   - Syslog (generic RFC3164/5424)
   - Generic (fallback)

## Helper Functions

### syslog_tag_dominant()

For syslog-tagged services, check if a tag dominates the sample:

```python
from logcrux.parsers.base import syslog_tag_dominant

@classmethod
def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
    # Only if "sudo" tag dominates the sample
    # Prevents a stray sudo line in mixed syslog from hijacking
    return syslog_tag_dominant(sample_lines, "sudo")
```

### Sample Slicing

When reading a file, logcrux reads first 100 lines as sample:

```python
def detect_parser(path: Optional[Path], log_lines: list[str]) -> LogParser:
    sample = log_lines[:100]  # Use first 100 for detection
    
    for parser_class in _PARSERS:
        if parser_class.can_parse(path, sample):
            return parser_class()
    
    return GenericParser()
```

## Parsing Implementation

### Timestamp Parsing

Use the `parse_rfc3164` and `parse_rfc5424` helpers for common formats:

```python
from datetime import datetime
import re

def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
    # Extract timestamp
    # Example: "2026-06-20T16:45:22+00:00"
    match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if not match:
        return None
    
    timestamp_str = match.group(1)
    try:
        timestamp = datetime.fromisoformat(timestamp_str)
    except ValueError:
        timestamp = None
    
    # ... extract other fields
    
    return ParsedEvent(
        timestamp=timestamp,
        severity=severity,
        source=source,
        message=message,
        raw=line,
        line_number=line_number,
        extra={...}
    )
```

### Severity Mapping

Map log format's severity to standard `Severity` enum:

```python
def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
    # Extract severity string from line
    severity_str = extract_severity(line)  # e.g., "ERROR"
    
    # Map to Severity enum
    severity_map = {
        "TRACE": Severity.DEBUG,
        "DEBUG": Severity.DEBUG,
        "INFO": Severity.INFO,
        "NOTICE": Severity.WARNING,
        "WARNING": Severity.WARNING,
        "ERROR": Severity.ERROR,
        "CRITICAL": Severity.CRITICAL,
        "FATAL": Severity.CRITICAL,
        "EMERGENCY": Severity.CRITICAL,
    }
    
    severity = severity_map.get(severity_str, Severity.UNKNOWN)
    
    return ParsedEvent(
        severity=severity,
        ...
    )
```

### Extra Fields

Capture format-specific fields:

```python
def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
    # For Nginx access log: extract IP, method, path, status
    match = re.match(
        r"(\S+) - - \[.*?\] \"(\S+) (\S+) (\S+)\" (\d+)",
        line
    )
    
    if not match:
        return None
    
    ip, method, path, protocol, status = match.groups()
    
    return ParsedEvent(
        ...,
        extra={
            "ip": ip,
            "method": method,
            "path": path,
            "protocol": protocol,
            "status": int(status),
        }
    )
```

## Parser Testing

Each parser should have tests in `tests/unit/test_parsers/`:

```python
# tests/unit/test_parsers/test_myformat.py

def test_can_parse_by_path():
    path = Path("/var/log/myformat.log")
    sample = ["Line 1", "Line 2"]
    assert MyFormatParser.can_parse(path, sample)

def test_can_parse_by_sample():
    path = None
    sample = ["[special_marker] message"]
    assert MyFormatParser.can_parse(path, sample)

def test_cannot_parse_wrong_format():
    path = Path("/var/log/nginx.log")
    sample = ["192.168.1.1 - - [...]"]
    assert not MyFormatParser.can_parse(path, sample)

def test_parse_line():
    parser = MyFormatParser()
    line = "2026-06-20T16:45:22 INFO app message"
    event = parser.parse_line(line, 1)
    
    assert event is not None
    assert event.timestamp.year == 2026
    assert event.severity == Severity.INFO
    assert event.source == "app"
    assert event.message == "message"

def test_parse_line_invalid():
    parser = MyFormatParser()
    line = "garbage that doesn't match format"
    event = parser.parse_line(line, 1)
    
    assert event is None  # Unparseable
```

## Common Pitfalls

### 1. Overly Broad Detection

```python
# ❌ BAD: Matches too many formats
if "[" in line and "]" in line:
    return True

# ✓ GOOD: Specific marker
if re.search(r"\[nginxd\-\d+\]", line):
    return True
```

### 2. Assuming Timestamps Exist

```python
# ❌ BAD: Crashes if timestamp missing
timestamp = datetime.fromisoformat(timestamp_str)

# ✓ GOOD: Handle gracefully
try:
    timestamp = datetime.fromisoformat(timestamp_str)
except ValueError:
    timestamp = None
```

### 3. Returning ParsedEvent for Unparseable Lines

```python
# ❌ BAD: Return dummy event if parse fails
if not match:
    return ParsedEvent(
        timestamp=None,
        severity=Severity.UNKNOWN,
        source="unknown",
        message=line,
        raw=line,
        line_number=line_number,
    )

# ✓ GOOD: Return None and let parser skip
if not match:
    return None
```

### 4. Not Handling Edge Cases

```python
# ❌ BAD: Doesn't handle empty lines
for line in sample_lines:
    if "pattern" in line:
        return True

# ✓ GOOD: Filter and handle empty
if not sample_lines:
    return False

for line in sample_lines:
    if line.strip() and "pattern" in line:
        return True
```

## Performance Considerations

- **Detection:** Called once per file analysis (fast)
- **Parsing:** Called for every line (must be O(1) per line)
- **Regex:** Precompile patterns at class level

```python
class MyFormatParser(LogParser):
    FORMAT_NAME = "myformat"
    
    # Compile regex once, not per parse_line call
    _LINE_PATTERN = re.compile(
        r"(\d{4}-\d{2}-\d{2}) (\S+) (.*)"
    )
    
    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        match = self._LINE_PATTERN.match(line)
        if not match:
            return None
        # ... fast extraction
```

---

**Last Updated:** July 2026
