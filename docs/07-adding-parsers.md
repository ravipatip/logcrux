# Adding New Parsers

This guide walks through adding a new log format parser to logcrux, with a complete example.

## Quick Checklist

- [ ] Create parser class in `logcrux/parsers/myformat.py`
- [ ] Implement `can_parse()` method (detection)
- [ ] Implement `parse_line()` method (parsing)
- [ ] Register in `logcrux/parsers/registry.py`
- [ ] Add test fixtures in `tests/fixtures/myformat.log`
- [ ] Write tests in `tests/unit/test_parsers/test_myformat.py`
- [ ] Verify detection doesn't match other formats
- [ ] Update docs (`docs/06-supported-log-types.md`)
- [ ] Run full test suite

## Example: Adding Exim Mail Parser

### Step 1: Create Parser File

Create `logcrux/parsers/exim.py`:

```python
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from logcrux.models import ParsedEvent, Severity
from logcrux.parsers.base import LogParser


class EximParser(LogParser):
    FORMAT_NAME = "exim"
    
    # Precompile regex pattern (efficient)
    _EXIM_PATTERN = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\[[\w\d.-]+\]) "
        r"(\w+) (\w+) (.*?)$"
    )
    
    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        """
        Detect Exim logs by:
        1. Path hint: /var/log/exim4/ or /var/log/exim/
        2. Sample content: Exim's distinctive format
        """
        # Path-based detection
        if path:
            path_str = str(path).lower()
            if "exim" in path_str and "log" in path_str:
                return True
        
        # Sample-based detection
        if not sample_lines:
            return False
        
        for line in sample_lines:
            # Exim format: "2026-06-20 16:45:22 [1.2.3.4] <= ... @"
            if cls._EXIM_PATTERN.match(line):
                return True
        
        return False
    
    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        """Parse an Exim log line."""
        match = self._EXIM_PATTERN.match(line)
        if not match:
            return None
        
        timestamp_str, host, direction, op_type, rest = match.groups()
        
        # Parse timestamp
        try:
            timestamp = datetime.strptime(
                timestamp_str, "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            timestamp = None
        
        # Determine severity and message
        if direction == "=>":
            # Mail delivered
            severity = Severity.INFO
            message = f"Delivered: {rest[:100]}"
        elif direction == "**":
            # Delivery failed
            severity = Severity.ERROR
            message = f"Failed: {rest[:100]}"
        elif direction == "==":
            # Processing
            severity = Severity.INFO
            message = f"Processing: {rest[:100]}"
        else:
            # Unknown
            severity = Severity.INFO
            message = rest[:100]
        
        # Extract extra fields
        extra = {
            "direction": direction,
            "operation": op_type,
        }
        
        # Try to extract recipient from rest
        if "@" in rest:
            recipient = rest.split()[-1] if rest.split() else None
            if recipient:
                extra["recipient"] = recipient
        
        return ParsedEvent(
            timestamp=timestamp,
            severity=severity,
            source="exim",
            message=message,
            raw=line,
            line_number=line_number,
            extra=extra,
        )
```

### Step 2: Register Parser

Edit `logcrux/parsers/registry.py`:

```python
# Add import at top
from logcrux.parsers.exim import EximParser

# Add to _PARSERS list in appropriate position
# (Exim is mail, so add with other mail parsers)
_PARSERS: list[type[LogParser]] = [
    # ... existing parsers ...
    
    # Mail / FTP
    PostfixParser,
    DovecotParser,
    EximParser,     # ← Add here
    FTPParser,
    
    # ... rest of parsers ...
]
```

**Position matters:** Parsers are tried in order. Mail parsers should be after syslog-tagged parsers but before generic syslog.

### Step 3: Add Test Fixtures

Create `tests/fixtures/exim.log` with sample Exim logs:

```
2026-06-20 16:45:22 [192.168.1.1] <= user@example.com U=user P=esmtp
2026-06-20 16:45:23 [mail.example.com] => recipient@other.com R=smtp
2026-06-20 16:45:24 [mail.example.com] ** user@failed.com F=<user@example.com> Timed out
2026-06-20 16:45:25 [192.168.1.2] <= postmaster@test.com
```

### Step 4: Write Unit Tests

Create `tests/unit/test_parsers/test_exim.py`:

```python
import pytest
from pathlib import Path
from logcrux.models import Severity
from logcrux.parsers.exim import EximParser


class TestEximParser:
    """Test Exim mail log parser."""
    
    def test_can_parse_by_path(self):
        """Detect by path hint."""
        parser_class = EximParser
        path = Path("/var/log/exim4/main.log")
        sample = ["dummy line"]
        
        assert parser_class.can_parse(path, sample) is True
    
    def test_can_parse_by_sample(self):
        """Detect by sample content."""
        parser_class = EximParser
        path = None
        sample = [
            '2026-06-20 16:45:22 [192.168.1.1] <= user@example.com'
        ]
        
        assert parser_class.can_parse(path, sample) is True
    
    def test_cannot_parse_wrong_format(self):
        """Don't match other formats."""
        parser_class = EximParser
        path = Path("/var/log/nginx.log")
        sample = ["192.168.1.1 - - [20/Jun/2026:16:45:22] GET /"]
        
        assert parser_class.can_parse(path, sample) is False
    
    def test_parse_delivery(self):
        """Parse successful delivery."""
        parser = EximParser()
        line = '2026-06-20 16:45:23 [mail.example.com] => recipient@other.com R=smtp'
        event = parser.parse_line(line, 1)
        
        assert event is not None
        assert event.severity == Severity.INFO
        assert event.source == "exim"
        assert "recipient@other.com" in event.message
        assert event.timestamp.hour == 16
    
    def test_parse_failure(self):
        """Parse delivery failure."""
        parser = EximParser()
        line = '2026-06-20 16:45:24 [mail.example.com] ** user@failed.com F=<user@example.com>'
        event = parser.parse_line(line, 2)
        
        assert event is not None
        assert event.severity == Severity.ERROR
        assert "Failed" in event.message
    
    def test_parse_receipt(self):
        """Parse incoming mail."""
        parser = EximParser()
        line = '2026-06-20 16:45:22 [192.168.1.1] <= user@example.com U=user P=esmtp'
        event = parser.parse_line(line, 3)
        
        assert event is not None
        assert event.severity == Severity.INFO
        assert "user@example.com" in event.message
        assert event.extra["direction"] == "<="
    
    def test_parse_invalid_line(self):
        """Handle unparseable lines."""
        parser = EximParser()
        line = "This is not an exim log line"
        event = parser.parse_line(line, 100)
        
        assert event is None


class TestEximDetectionPrecision:
    """Ensure Exim parser doesn't false-match other formats."""
    
    def test_does_not_match_syslog(self):
        """Don't match generic syslog."""
        parser_class = EximParser
        path = Path("/var/log/syslog")
        sample = [
            "2026-06-20T16:45:22+00:00 hostname kernel: message"
        ]
        
        assert parser_class.can_parse(path, sample) is False
    
    def test_does_not_match_postfix(self):
        """Don't match Postfix mail logs."""
        parser_class = EximParser
        path = None
        sample = [
            "2026-06-20T16:45:22+00:00 hostname postfix/smtp[12345]: ABC123: to=<user@example.com>"
        ]
        
        assert parser_class.can_parse(path, sample) is False
```

### Step 5: Verify Registration

```bash
# Check parser is registered
python -c "from logcrux.parsers.registry import _PARSERS; print([p.FORMAT_NAME for p in _PARSERS])"

# Should show 'exim' in the list
```

### Step 6: Run Tests

```bash
# Test the new parser
pytest tests/unit/test_parsers/test_exim.py -v

# Run all parser tests to ensure no regressions
pytest tests/unit/test_parsers/ -v

# Run full test suite
pytest -v
```

### Step 7: Test End-to-End

```bash
# Create a test log file
cat > /tmp/test_exim.log << 'EOF'
2026-06-20 16:45:22 [192.168.1.1] <= user@example.com
2026-06-20 16:45:23 [mail.example.com] => recipient@other.com R=smtp
2026-06-20 16:45:24 [mail.example.com] ** user@failed.com F=<user@example.com>
EOF

# Run logcrux
logcrux /tmp/test_exim.log

# Should output: "Format detected: exim"
```

### Step 8: Update Documentation

Edit `docs/06-supported-log-types.md` and add your parser to the list. Example:

```markdown
## Mail & FTP (5)

#### 13. Exim Parser
**Format Name:** `exim`  
**File Patterns:** `/var/log/exim4/main.log*`, `/var/log/exim/log*`  
**Format:** Timestamp [host] direction operation details

\`\`\`
2026-06-20 16:45:22 [192.168.1.1] <= user@example.com U=user P=esmtp
\`\`\`

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: INFO (for deliveries), ERROR (for failures)
- `source`: exim
- `extra`: `{direction, operation, recipient}`

**Detects:** Mail failures, bounce patterns, TLS issues
```

## Detection Best Practices

### 1. Be Specific

```python
# ❌ BAD: Too generic
if "2026-06" in line:
    return True

# ✓ GOOD: Specific to format
if re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[.*?\].*<=", line):
    return True
```

### 2. Use Syslog Helper for Tagged Services

```python
from logcrux.parsers.base import syslog_tag_dominant

@classmethod
def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
    # Use helper to check if 'myservice' tag dominates
    return syslog_tag_dominant(sample_lines, "myservice")
```

### 3. Handle Empty Sample

```python
@classmethod
def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
    if not sample_lines:
        # If no sample, only rely on path
        return path and "myformat" in str(path).lower()
    # ... rest of logic
```

### 4. Order Registration Carefully

**Priority order:**
1. Path-specific hints first (highest precision)
2. Format-specific patterns
3. Syslog-tagged services (use `syslog_tag_dominant`)
4. Structured logs (JSON-based, order doesn't matter)
5. Generic catch-alls last

### 5. Test Against Similar Formats

```python
def test_does_not_match_similar_format():
    """Ensure we don't claim formats meant for other parsers."""
    # If your format is close to another, test extensively
    parser_class = MyFormatParser
    
    # Test against all close competitors
    similar_samples = [
        nginx_sample,
        apache_sample,
        haproxy_sample,
        # ...
    ]
    
    for sample in similar_samples:
        assert parser_class.can_parse(None, sample) is False
```

## Common Issues

### Issue: Parser Matches Wrong Files

**Problem:** Your parser's `can_parse()` is too broad and matches files it shouldn't.

**Solution:** Make detection more specific:
```python
# ❌ Before: Matches too many
if "[" in line:
    return True

# ✓ After: Specific marker
if "myformat[" in line:
    return True
```

### Issue: Parser in Wrong Position

**Problem:** Your parser matches before a more specific parser.

**Solution:** Move it in `registry.py`:
```python
_PARSERS = [
    # Most specific first
    KubernetesParser,  # Very specific path
    NginxErrorParser,  # Format-specific
    MyNewParser,       # Should be here
    SyslogParser,      # Generic
    GenericParser,     # Last resort
]
```

### Issue: Timestamp Parsing Fails

**Problem:** Lines with unparseable timestamps are skipped.

**Solution:** Handle gracefully:
```python
try:
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
except ValueError:
    timestamp = None  # Allow None, don't crash

return ParsedEvent(
    timestamp=timestamp,  # Can be None
    ...
)
```

---

**Last Updated:** July 2026
