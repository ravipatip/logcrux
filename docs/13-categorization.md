# Categorization

logcrux categorizes incidents into 7 categories. This document explains each and how categorization works.

## At a glance

| category | triggered by | exit |
|---|---|---|
| `auth_brute_force` | SSH/SASL/DB auth-failure clusters, firewall port-22 blocks | 3 |
| `http_overload` | 5xx spikes, 502/503, upstream failures | 3 |
| `network_issue` | timeouts, replication lag, CNI failures | 3 |
| `oom` | OOM-killed processes, memory allocation failures | 4 |
| `service_crash` | backend down, FATAL/PANIC, crash-loop restarts | 4 |
| `disk_full` | "no space left on device" | 4 |
| `config_error` | invalid parameters, malformed settings | 4 |

Severity follows the category, not just confidence: a high-confidence
`auth_brute_force` is still exit 3, while `oom` and `service_crash` are
always exit 4 once clustered. Reaching that CRITICAL state also
requires the failure to actually be logged at error severity and in a
parseable format, not just to have happened. A database's own LOG-level
recovery trace, or a crash backtrace no parser recognizes, won't trip
it: feed logcrux the stream where the failure is recorded at error
severity (kernel/syslog, journalctl, orchestrator events).

## The 7 Categories

### OOM — Out-of-Memory

**Trigger:** Deterministic pattern match: "killed process" + "out of memory"

**Example:**
```
Out of memory: Kill process 1234 (java) score 100 or sacrifice child
```

**Typical Scenario:**
- Java/Python app consuming all RAM
- Memory leak growing over time
- System runs out of memory, kernel kills largest process

**Remediation:**
1. Check memory usage: `free -h`, `top`
2. Identify memory hog: `ps aux --sort=-%mem | head`
3. Increase RAM or optimize app
4. Check for memory leaks: `valgrind`, `jmap`
5. Set memory limits: cgroups, JVM -Xmx flag

---

### AUTH_BRUTE_FORCE — Brute-Force Authentication Attack

**Trigger:** Cluster of failed auth attempts OR AI classifier

**Example:**
```
47 failed SSH attempts from 192.168.1.100 in 5 minutes
1 successful login post-attack
```

**Typical Scenario:**
- Attacker probing accounts (admin, root, test)
- Weak password on a service
- Compromised account discovered post-attack

**Remediation:**
1. Block attacker: `sudo ufw insert 1 deny from 192.168.1.100`
2. Reset password immediately
3. Audit who accessed what: `grep "Accepted" /var/log/auth.log`
4. Check for unauthorized changes: `sudo lastlog -u root`
5. Enable fail2ban or rate limiting

**Prevention:**
- SSH key-only auth (disable passwords)
- Rate limiting: `MaxAuthTries 3` in sshd_config
- IP allowlist if possible
- VPN/bastion host for remote access

---

### HTTP_OVERLOAD — HTTP Service Overload

**Trigger:** High 5xx error rate OR AI classifier

**Example:**
```
100 HTTP 502/503 errors in 5 minutes
Upstream connection timeouts
```

**Typical Scenario:**
- Backend service crashing/overloaded
- Database connection pool exhausted
- Resource limits reached (CPU, memory)
- Cascading failure (one service fails, others timeout)

**Remediation:**
1. Check backend health: `curl -I http://backend:8080/health`
2. Check resource usage: `top`, `df`, free`
3. Scale horizontally: Add more backend instances
4. Check logs: Application error logs for OOM/crashes
5. Restart service: `systemctl restart myapp`
6. Monitor connections: `netstat -an | grep ESTABLISHED | wc -l`

**Prevention:**
- Load balancing across multiple instances
- Health checks and auto-recovery
- Resource limits/quotas
- Connection pooling with limits
- Circuit breaker pattern for dependent services

---

### DISK_FULL — Filesystem Out of Space

**Trigger:** Deterministic pattern match: "no space left on device"

**Example:**
```
write error: No space left on device
```

**Typical Scenario:**
- Log files growing unbounded
- Database transaction log filling disk
- Temp files accumulating
- Application dumps/core files

**Remediation:**
1. Check disk: `df -h`
2. Find large files/dirs: `du -sh /* | sort -h`
3. Delete old logs: `find /var/log -mtime +30 -delete`
4. Clean package cache: `apt clean` or `yum clean all`
5. Delete core dumps: `rm /var/crash/*`
6. Check journal: `journalctl --vacuum=2w`
7. Add storage if persistent: Resize partition or add disk

**Prevention:**
- Log rotation: logrotate, systemd journal limits
- Application log levels (don't log everything)
- Periodic cleanup scripts
- Monitoring: Alert at 80% full

---

### SERVICE_CRASH — Service/Process Crash

**Trigger:** Deterministic pattern match: "exited with signal", "SIGSEGV", etc.

**Example:**
```
[error] 12345#0: *999 segmentation fault at 0x0000000100123456
nginx: master process exited with code 1
```

**Typical Scenario:**
- Code bug in application
- Memory corruption
- Null pointer dereference
- Stack overflow
- Signal handler issue (kill -9, SIGKILL)

**Remediation:**
1. Check exit code: Non-zero means error
2. Check signal: SIGSEGV (11), SIGABRT (6), SIGKILL (9)
3. Examine logs: Core dump, stderr output
4. Restart service: `systemctl restart myapp`
5. Investigate root cause:
   - Update application
   - Check system library versions
   - Run under debugger locally
6. Monitor: Alert on repeated crashes

**Prevention:**
- Code review and testing
- Use memory-safe languages if possible
- Enable AddressSanitizer in development
- Set resource limits (stack size, file size)
- Systemd auto-restart: `Restart=always`

---

### CONFIG_ERROR — Configuration Error

**Trigger:** AI classifier (pattern-based detection limited)

**Example:**
```
syntax error at line 5: unexpected token
invalid option 'foo' for directive 'bar'
```

**Typical Scenario:**
- Typo in config file
- Changed option name (version mismatch)
- Wrong value type (string vs number)
- Missing required option
- Recent config deployment with error

**Remediation:**
1. Validate config syntax: `nginx -t`, `apache2ctl -t`
2. Review recent changes: `git log -p /etc/myapp/config.yml`
3. Fix syntax error in file
4. Reload service: `systemctl reload myapp`
5. Monitor for startup errors

**Prevention:**
- Schema validation before deployment
- Config linting tools
- Test in staging before production
- Version control for configs
- Code review for changes

---

### NETWORK_ISSUE — Network Connectivity Problem

**Trigger:** AI classifier (pattern-based detection limited)

**Example:**
```
Connection reset by peer
Temporary failure in name resolution
Network unreachable
```

**Typical Scenario:**
- DNS resolution failing
- Network interface down
- Firewall blocking connection
- Upstream service unreachable
- Network timeout on remote call

**Remediation:**
1. Check network: `ping 8.8.8.8`, `ip addr`, `ip route`
2. Check DNS: `nslookup example.com`, `dig example.com`
3. Check firewall: `sudo iptables -L`, `sudo ufw status`
4. Check service: `ss -an | grep :port`
5. Check routing: `traceroute destination`
6. Restart network: `systemctl restart networking`

**Prevention:**
- Redundant network paths
- DNS caching/fallback
- Firewall rules review
- Network monitoring/alerting
- Graceful degradation for network failures

---

### UNKNOWN — Unclassifiable Incident

**Trigger:** No clear pattern OR confidence below threshold

**Example:**
```
Unusual error that doesn't match known categories
```

**Typical Scenario:**
- Novel incident type
- Rare/unexpected failure
- Multiple issues overlapping
- Insufficient data to classify

**Remediation:**
1. Manual investigation required
2. Review full logs context
3. Check system state: processes, memory, disk, network
4. Search documentation/forums
5. Contact vendor support if applicable

---

## Categorization Logic

### Priority

1. **Deterministic signals first** (highest precision)
   - oom_event → OOM
   - disk_full → DISK_FULL
   - service_crash → SERVICE_CRASH
   - auth_failure_cluster → AUTH_BRUTE_FORCE

2. **AI classifier second** (if no deterministic signal)
   - Uses ONNX model on representative messages
   - Returns confidence score
   - Falls back to UNKNOWN if below threshold

### Decision Tree

```
Is there an OOM pattern?
  Yes → OOM
  No  ↓
Is there a DISK_FULL pattern?
  Yes → DISK_FULL
  No  ↓
Is there a SERVICE_CRASH pattern?
  Yes → SERVICE_CRASH
  No  ↓
Is there an AUTH_FAILURE cluster?
  Yes → AUTH_BRUTE_FORCE
  No  ↓
Run AI classifier
  ↓
Confidence >= threshold?
  Yes → Return category
  No  → UNKNOWN
```

## Confidence Levels

**Confidence Range:** 0.0 to 1.0

**Interpretation:**
- **0.0-0.14:** Below random (7 categories → 1/7 = 0.14)
- **0.14-0.35:** Marked UNKNOWN (below default threshold)
- **0.35-0.7:** Moderate (WARNING level incident)
- **0.7-1.0:** High (CRITICAL level incident)

**Usage:** Impacts severity level of incident summary.

## Testing Categorization

```bash
# Analyze log with known incident
logcrux tests/fixtures/auth_brute_force.log
# Expected: AUTH_BRUTE_FORCE category

# Check confidence
logcrux /var/log/syslog --json | jq '.category, .confidence'
```

---

**Last Updated:** July 2026
