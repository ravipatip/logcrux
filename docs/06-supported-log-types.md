# Supported Log Types

logcrux supports **209 log format parsers** (208 format-specific + a generic fallback) covering all common Linux services, cloud-native infrastructure, security tooling, and modern observability stacks. Every one of the 209 is listed in the [complete parser index](#complete-parser-index) at the end of this document; the most commonly used formats additionally get a full worked example below (format name, file patterns, a sample log line, extracted fields, and what it detects).

## Quick Reference Table

| Category | Parser count | Representative formats |
|----------|-------------|----------------------|
| **Web Servers & Proxies** | 16 | alb, apache-access, apache-error, caddy, cloudfront, envoy, haproxy, iis, … |
| **Databases** | 17 | cassandra, clickhouse, cockroachdb, druid, elasticsearch, flink, hbase, hive, … |
| **Containers & Cloud-Native** | 17 | cloudinit, cloudtrail, cloudwatch, composelog, cri, docker, fluentbit, gcp, … |
| **System & Auth** | 12 | apparmor, auditd, cron, fail2ban, journald, kernel, krb5kdc, secure, … |
| **Security / SIEM** | 19 | azure, cef, ciscoasa, cloudflare, falco, fortigate, gelf, kubeaudit, … |
| **Identity & Access Mgmt** | 5 | pingaccess, pingauthorize, pingdirectory, pingfederate, pingintelligence |
| **Observability / Agents** | 16 | bunyan, datadog, filebeat, kibana, logfmt, logrus, logstash, monit, … |
| **Mail** | 8 | dovecot, exim, opendkim, opensmtpd, postfix, rspamd, sendmail, spamassassin |
| **Message Queues** | 6 | activemq, kafka, mosquitto, nats, pulsar, rabbitmq |
| **Application Frameworks** | 18 | airflow, django, gostdlib, gunicorn, jetty, laravel, log4j, phoenix, … |
| **Infrastructure, HA & DNS** | 17 | coredns, dnsmasq, etcd, firewalld, freeradius, hashicorp, keepalived, keycloak, … |
| **Network / VPN** | 8 | frr, mikrotik, openvpn, pihole, tailscale, unifi, wireguard, wpa_supplicant |
| **Storage & Virtualization** | 10 | ceph, glusterfs, libvirt, lxc, mdadm, minio, podman, qemu, … |
| **Big Data** | 4 | hadoop, jvmgc, solr, spark |
| **Build & Package Mgmt** | 8 | apthistory, bazel, dpkg, gradle, maven, npm, pip, yum |
| **Linux Daemons** | 16 | asterisk, avahi, bluetoothd, chrony, cups, dbus, dhcpd, ftp, … |
| **Other Daemons** | 11 | ansible, celery, certbot, chef, clamav, jenkins, puppet, rsyncd, … |
| **Fallback** | 1 | generic |

**Total: 209 parsers**, every one listed exactly once in the [complete index](#complete-parser-index) below.

---

## Detailed Parser Reference

The entries below give full worked examples for the most commonly used formats; all of them follow the same `FORMAT_NAME` / `can_parse` / `parse_line` structure. For the remaining formats — and as a complete cross-check that nothing is missing — see the [Complete Parser Index](#complete-parser-index) at the end of this document, which lists all 209 parsers with their category and source file.

### Web Servers (nginx, apache, haproxy, squid, json-access — 5+)

#### 1. Nginx Access Parser
**Format Name:** `nginx_access`  
**File Patterns:** `/var/log/nginx/access.log*`, `/var/log/*nginx*access*`  
**Format:** Combined/Common Log Format (CLF) with optional extensions

```
192.168.1.1 - - [20/Jun/2026:16:45:22 +0000] "GET /api/v1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: INFO (if 2xx), WARNING (if 4xx), ERROR (if 5xx)
- `source`: nginx
- `extra`: `{ip, user, method, path, protocol, status, bytes_sent, referer, user_agent}`

**Detects:** HTTP status codes, slow requests, 5xx errors, redirects

---

#### 2. Nginx Error Parser
**Format Name:** `nginx_error`  
**File Patterns:** `/var/log/nginx/error.log*`, `/var/log/*nginx*error*`  
**Format:** Timestamp [severity] PID#TID: message

```
2026/06/20 16:45:22 [error] 12345#0: *999 connect() failed (111: Connection refused)
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: error, warn, crit, alert, emerg, notice, info, debug
- `source`: nginx
- `extra`: `{pid, tid, connection_id, error_code, error_message}`

**Detects:** Connection failures, timeouts, permission errors, buffer issues

---

#### 3. Apache Access Parser
**Format Name:** `apache_access`  
**File Patterns:** `/var/log/apache2/access.log*`, `/var/log/httpd/access_log*`  
**Format:** Combined Log Format (CLF)

```
192.168.1.1 - user [20/Jun/2026:16:45:22 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: Derived from HTTP status
- `source`: apache
- `extra`: `{ip, user, method, path, protocol, status, bytes_sent}`

**Detects:** Request patterns, status code distribution, client IPs

---

#### 4. Apache Error Parser
**Format Name:** `apache_error`  
**File Patterns:** `/var/log/apache2/error.log*`, `/var/log/httpd/error_log*`  
**Format:** [Timestamp] [severity:module] message

```
[Wed Jun 20 16:45:22 2026] [error:core] [pid 12345:tid 67890] Configuration error: ...
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: emerg, alert, crit, error, warn, notice, info, debug
- `source`: apache
- `extra`: `{module, pid, tid, error_code}`

**Detects:** Configuration errors, permission issues, child process failures

---

### Databases (5)

#### 5. PostgreSQL Parser
**Format Name:** `postgresql`  
**File Patterns:** `/var/log/postgresql/postgresql.log*`, `/var/log/postgres*`  
**Format:** Timestamp [PID] [user@database] [STATEMENT] severity: message

```
2026-06-20 16:45:22.123 UTC [12345] user@mydb [SELECT] ERROR: syntax error
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: debug5-debug1, log, info, notice, warning, error, fatal, panic
- `source`: postgresql
- `extra`: `{pid, user, database, statement, line_number, function}`

**Detects:** Query errors, authentication failures, connection issues, deadlocks

---

#### 6. MySQL Parser
**Format Name:** `mysql`  
**File Patterns:** `/var/log/mysql/error.log*`, `/var/log/*mysql*.log*`  
**Format:** Timestamp [severity] message (varies by version)

```
2026-06-20T16:45:22.123456Z 12345 [ERROR] Slave IO thread got fatal error
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: system, error, warning, note
- `source`: mysql
- `extra`: `{pid, error_code, subsystem}`

**Detects:** Replication errors, connection failures, table locks, permission issues

---

#### 7. MongoDB Parser
**Format Name:** `mongodb`  
**File Patterns:** `/var/log/mongodb/mongod.log*`  
**Format:** JSON (modern) or legacy text format

```json
{"t":{"$date":"2026-06-20T16:45:22.123Z"},"s":"E","c":"NETWORK","id":64363,"msg":"..."}
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: I (info), W (warning), E (error), F (fatal)
- `source`: mongodb
- `extra`: `{component, error_code, operation}`

**Detects:** Connection errors, replication lag, query timeouts, disk space issues

---

#### 8. Redis Parser
**Format Name:** `redis`  
**File Patterns:** `/var/log/redis*`, `/var/lib/redis/redis.log*`  
**Format:** Timestamp * [severity] message

```
20 Jun 2026 16:45:22.123 * [12345:0] <error> ...
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: info, warning, error, debug
- `source`: redis
- `extra`: `{pid, database, command}`

**Detects:** Connection failures, memory limits, persistence issues, slowlog events

---

#### 9. Elasticsearch Parser
**Format Name:** `elasticsearch`  
**File Patterns:** `/var/log/elasticsearch*`, `/var/log/*elastic*`  
**Format:** JSON or structured text

```json
{"@timestamp":"2026-06-20T16:45:22.123Z","log.level":"ERROR","logger_name":"elasticsearch","message":"..."}
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: TRACE, DEBUG, INFO, WARN, ERROR, FATAL
- `source`: elasticsearch
- `extra`: `{node, shard, index, error_code}`

**Detects:** Shard failures, index issues, cluster problems, GC warnings

---

### Middleware & App Servers (3)

#### 10. Gunicorn Parser
**Format Name:** `gunicorn`  
**File Patterns:** `/var/log/gunicorn*`, Syslog with `gunicorn` tag  
**Format:** Timestamp [PID] [severity] message

```
2026-06-20 16:45:22,123 [12345] [error] Error handling request: ...
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: debug, info, warning, error
- `source`: gunicorn
- `extra`: `{pid, worker_id, request_details}`

**Detects:** Worker crashes, request timeouts, binding errors, permission issues

---

#### 11. PHP-FPM Parser
**Format Name:** `phpfpm`  
**File Patterns:** `/var/log/php-fpm*`, Syslog with `php-fpm` tag  
**Format:** Timestamp [severity] message

```
2026-06-20T16:45:22+00:00] ERROR fpm_event_epoll_ctl() failed ...
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: ALERT, NOTICE, WARNING, ERROR
- `source`: phpfpm
- `extra`: `{process, pool_name, error_code}`

**Detects:** Pool exhaustion, script errors, configuration issues, pool slowlog

---

#### 12. Tomcat Parser
**Format Name:** `tomcat`  
**File Patterns:** `/opt/tomcat/logs/catalina.out*`, `/var/log/tomcat*`  
**Format:** Timestamp severity [module] message

```
2026-06-20 16:45:22.123 ERROR [catalina-exec-10] org.apache.catalina...
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: SEVERE, WARNING, INFO, FINE, FINER, FINEST
- `source`: tomcat
- `extra`: `{thread, class, package}`

**Detects:** Deployment failures, WAR errors, connector issues, memory pressure

---

### Message Queues (2)

#### 13. Kafka Parser
**Format Name:** `kafka`  
**File Patterns:** `/opt/kafka/logs*`, `/var/log/kafka*`  
**Format:** Timestamp [severity] message

```
[2026-06-20 16:45:22,123] INFO Recovering UncleanLeaderElectionState (kafka.server.ReplicaManager)
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: TRACE, DEBUG, INFO, WARN, ERROR, FATAL
- `source`: kafka
- `extra`: `{broker_id, topic, partition, error_code}`

**Detects:** Broker failures, rebalancing issues, leader elections, lag problems

---

#### 14. RabbitMQ Parser
**Format Name:** `rabbitmq`  
**File Patterns:** `/var/log/rabbitmq*`, `/var/lib/rabbitmq/log*`  
**Format:** Timestamp [severity] message

```
2026-06-20 16:45:22.123 [info] <0.12345.6> ...
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: debug, info, warning, error
- `source`: rabbitmq
- `extra`: `{pid, node, exchange, queue, error_code}`

**Detects:** Connection failures, memory alarms, queue backing up, authentication issues

---

### Proxies & Load Balancers (2)

#### 15. HAProxy Parser
**Format Name:** `haproxy`  
**File Patterns:** `/var/log/haproxy*`, Syslog with `haproxy` tag  
**Format:** Timestamp hostname haproxy[pid]: client_ip:port backend/server connection_code ...

```
2026-06-20T16:45:22+00:00 myhost haproxy[12345]: 192.168.1.1:54321 web/server01 500 23ms
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: Derived from HTTP/TCP codes
- `source`: haproxy
- `extra`: `{client_ip, backend, server, http_code, bytes_read, bytes_sent}`

**Detects:** Backend server failures, connection timeouts, HTTP errors, queue overflows

---

#### 16. Squid Proxy Parser
**Format Name:** `squid` (supports both CLF and native format)  
**File Patterns:** `/var/log/squid/access.log*`, `/var/log/squid/cache.log*`  
**Format:** Timestamp millis source_ip status bytes method URL user hierarchy/server content_type

```
2026/06/20 16:45:22.123 12345 192.168.1.1 TCP_HIT/200 1234 GET http://example.com/ user DIRECT/1.2.3.4 text/html
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: Derived from HTTP status
- `source`: squid
- `extra`: `{client_ip, http_code, bytes, method, url, user, hierarchy}`

**Detects:** Cache misses, upstream errors, denied requests, SSL bumps issues

---

### System & Kernel (4)

#### 17. Syslog (Generic)
**Format Name:** `syslog`  
**File Patterns:** `/var/log/syslog*`, `/var/log/messages*`  
**Format:** RFC3164 or RFC5424 syslog

```
2026-06-20T16:45:22+00:00 myhost kernel: Out of memory: Kill process 12345 (app) score 100
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: debug, info, notice, warning, error, critical, alert, emergency
- `source`: kernel, app, systemd, etc.
- `extra`: Varies by source

**Detects:** OOM kills, disk full, service failures, security events

---

#### 18. Kernel/Dmesg Parser
**Format Name:** `kernel`  
**File Patterns:** `/var/log/kern.log*`, `/var/log/dmesg*`  
**Format:** Timestamp [boot_id] message

```
[  12.345678] systemd[1]: Started Example Service.
[ 234.567890] Out of memory: Kill process 12345 (app) score 100
```

**Extracted Fields:**
- `timestamp`: Relative or absolute (depends on dmesg vs kern.log)
- `severity`: Derived from message content
- `source`: kernel
- `extra`: `{subsystem, error_code}`

**Detects:** OOM kills, CPU throttling, disk errors, module load failures

---

#### 19. Journald Parser
**Format Name:** `journald`  
**File Patterns:** `/var/log/journal/*`, stdin with journalctl output  
**Format:** Systemd journal JSON

```json
{"__CURSOR":"...","__REALTIME_TIMESTAMP":"1687...","_HOSTNAME":"myhost","PRIORITY":"3","_COMM":"kernel","MESSAGE":"Out of memory..."}
```

**Extracted Fields:**
- `timestamp`: From __REALTIME_TIMESTAMP
- `severity`: From PRIORITY (systemd priority)
- `source`: From _COMM or _SYSTEMD_UNIT
- `extra`: All journal fields (PID, UID, GID, boot_id, etc.)

**Detects:** All journald sources (kernel, systemd services, applications)

---

#### 20. Auditd Parser
**Format Name:** `auditd`  
**File Patterns:** `/var/log/audit/audit.log*`  
**Format:** type=XXX msg=audit(...): field=value field=value

```
type=EXECVE msg=audit(1687288322.123:45): argc=2 a0="command" a1="arg1"
```

**Extracted Fields:**
- `timestamp`: From audit timestamp
- `severity`: warning (elevated for security events)
- `source`: auditd
- `extra`: `{audit_type, syscall, uid, gid, command, result, error_code}`

**Detects:** Unauthorized commands, failed syscalls, policy violations, file modifications

---

### Security & Authentication (5)

#### 21. Secure Parser (SSH/PAM)
**Format Name:** `secure`  
**File Patterns:** `/var/log/auth.log*`, `/var/log/secure*`  
**Format:** Syslog with sshd/sudo/login tags

```
2026-06-20T16:45:22+00:00 myhost sshd[12345]: Invalid user admin from 192.168.1.1 port 54321
2026-06-20T16:45:23+00:00 myhost sshd[12345]: Failed password for invalid user admin from 192.168.1.1 port 54321 ssh2
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: warning, error (for failures/denials)
- `source`: sshd, sudo, su, login, etc.
- `extra`: `{user, source_ip, port, auth_method, accepted/rejected}`

**Detects:** Brute-force attacks, invalid users, key-based auth failures, sudo usage

---

#### 22. Fail2Ban Parser
**Format Name:** `fail2ban`  
**File Patterns:** `/var/log/fail2ban.log*`  
**Format:** Timestamp fail2ban action [jail] message

```
2026-06-20 16:45:22,123 fail2ban.actions [sshd]: NOTICE [sshd] Ban 192.168.1.1
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG
- `source`: fail2ban
- `extra`: `{jail, action, ip_address, hostname}`

**Detects:** IP bans, unban events, filter issues, jail status changes

---

#### 23. UFW Parser
**Format Name:** `ufw`  
**File Patterns:** `/var/log/ufw.log*`, Syslog with `UFW` tag  
**Format:** Timestamp hostname UFW [rule] IN=eth0 OUT=eth1 ... DPT=port

```
2026-06-20T16:45:22+00:00 myhost kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.168.1.1 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: Derived from rule (ALLOW/DROP/REJECT)
- `source`: ufw
- `extra`: `{action, interface, protocol, source_ip, destination_ip, port}`

**Detects:** Port scan patterns, bruteforce access attempts, unusual protocols

---

#### 24. Cron Parser
**Format Name:** `cron`  
**File Patterns:** `/var/log/cron*`, Syslog with `CRON` tag  
**Format:** Syslog with CRON tags

```
2026-06-20T16:45:22+00:00 myhost CRON[12345]: (user) CMD (command)
2026-06-20T16:45:22+00:00 myhost CRON[12345]: (user) FAILED (exit code 127)
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: Derived from execution result
- `source`: cron
- `extra`: `{user, pid, command, exit_code}`

**Detects:** Failed cron jobs, missing commands, execution timeouts

---

#### 25. Sudo Parser
**Format Name:** `sudo`  
**File Patterns:** `/var/log/auth.log*`, Syslog with `sudo` tag  
**Format:** Syslog with sudo tags

```
2026-06-20T16:45:22+00:00 myhost sudo[12345]: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash
2026-06-20T16:45:23+00:00 myhost sudo[12345]: user : command not allowed
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: warning (for denials/authentication failures)
- `source`: sudo
- `extra`: `{user, tty, pwd, target_user, command, result}`

**Detects:** Privilege escalation attempts, unauthorized commands, sudoers changes

---

### Mail & FTP (5)

#### 26. Postfix Parser
**Format Name:** `postfix`  
**File Patterns:** `/var/log/mail.log*`, `/var/log/mail/*`, Syslog with `postfix` tag  
**Format:** Syslog with postfix tags

```
2026-06-20T16:45:22+00:00 myhost postfix/smtp[12345]: ABC123: to=<user@example.com>, relay=mx.example.com[1.2.3.4], status=sent
2026-06-20T16:45:23+00:00 myhost postfix/local[12345]: ABC123: to=<user@localhost>, relay=local, status=bounced
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: error (for bounces), info (for deliveries)
- `source`: postfix
- `extra`: `{queue_id, from, to, relay, status, error_code}`

**Detects:** Mail loop, spam filter triggers, authentication failures, queue backlog

---

#### 27. Dovecot Parser
**Format Name:** `dovecot`  
**File Patterns:** `/var/log/dovecot*`, Syslog with `dovecot` tag  
**Format:** Syslog with dovecot tags

```
2026-06-20T16:45:22+00:00 myhost dovecot[12345]: imap-login: Disconnected (auth failed): user=<user@example.com>, method=PLAIN, ...
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: warning (for failures), info (for operations)
- `source`: dovecot
- `extra`: `{service, user, reason, protocol, ip}`

**Detects:** Authentication failures, protocol errors, quota limits, TLS issues

---

#### 28. Exim (Mail) Parser
**Already listed above (Middleware section)**

---

#### 29. FTP Parser
**Format Name:** `ftp`  
**File Patterns:** `/var/log/ftp*`, Syslog with `ftpd` tag  
**Format:** Syslog with FTP operation logs

```
2026-06-20T16:45:22+00:00 myhost ftpd[12345]: USER user from 192.168.1.1 (192.168.1.1) : LOGIN SUCCESSFUL
2026-06-20T16:45:22+00:00 myhost ftpd[12345]: [192.168.1.1] Failed FTP login attempt
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: error (for failures), info (for operations)
- `source`: ftpd
- `extra`: `{user, ip, operation, status}`

**Detects:** Brute-force attacks, failed uploads, unusual file transfers

---

#### 30. Vsftpd Parser
**Format Name:** `vsftpd`  
**File Patterns:** `/var/log/vsftpd.log*`, Syslog with `vsftpd` tag  
**Format:** Syslog with vsftpd-specific fields

```
2026-06-20T16:45:22+00:00 myhost vsftpd[12345]: [user] OK LOGIN. Client "192.168.1.1"
2026-06-20T16:45:22+00:00 myhost vsftpd[12345]: [user] FAILED LOGIN. Client "192.168.1.1"
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: error, info
- `source`: vsftpd
- `extra`: `{user, client_ip, operation, status}`

**Detects:** Failed login attempts, file transfers, directory operations

---

### DNS & Network Services (4)

#### 31. BIND/Named Parser
**Format Name:** `named`  
**File Patterns:** `/var/log/named*`, Syslog with `named` tag  
**Format:** Syslog with named logs

```
2026-06-20T16:45:22+00:00 myhost named[12345]: error (network unreachable) resolving 'example.com/A/IN'
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: Derived from message
- `source`: named
- `extra`: `{zone, error_code, query_type}`

**Detects:** Resolution failures, DNSSEC errors, zone transfer issues, upstream problems

---

#### 32. Dnsmasq Parser
**Format Name:** `dnsmasq`  
**File Patterns:** `/var/log/dnsmasq*`, Syslog with `dnsmasq` tag  
**Format:** Syslog with dnsmasq logs

```
2026-06-20T16:45:22+00:00 myhost dnsmasq[12345]: query[A] example.com from 192.168.1.1
2026-06-20T16:45:22+00:00 myhost dnsmasq[12345]: reply example.com is 1.2.3.4
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: info
- `source`: dnsmasq
- `extra`: `{query_type, domain, source_ip, answer}`

**Detects:** Resolution patterns, DHCP issues, DNS spoofing attempts

---

#### 33. Chrony/NTP Parser
**Format Name:** `chrony`  
**File Patterns:** `/var/log/chrony*`, Syslog with `chronyd` tag  
**Format:** Syslog with NTP operation logs

```
2026-06-20T16:45:22+00:00 myhost chronyd[12345]: Source 91.189.89.199 offline
2026-06-20T16:45:23+00:00 myhost chronyd[12345]: System time wrong by 1234.567 seconds (step)
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: warning (for issues), info (for sync)
- `source`: chronyd
- `extra`: `{ntp_source, offset, stratum}`

**Detects:** Time sync issues, source failures, clock stepping events

---

#### 34. DHCP Parser
**Format Name:** `dhcpd`  
**File Patterns:** `/var/log/syslog*`, Syslog with `dhcpd` tag  
**Format:** Syslog with DHCP operation logs

```
2026-06-20T16:45:22+00:00 myhost dhcpd[12345]: DHCPDISCOVER from aa:bb:cc:dd:ee:ff
2026-06-20T16:45:22+00:00 myhost dhcpd[12345]: DHCPACK on 192.168.1.100 to aa:bb:cc:dd:ee:ff
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: warning (for errors), info (for operations)
- `source`: dhcpd
- `extra`: `{mac_address, ip_address, operation, error_code}`

**Detects:** DHCP pool exhaustion, conflicts, duplicate leases

---

### Samba/SMB (1)

#### 35. Samba Parser
**Format Name:** `samba`  
**File Patterns:** `/var/log/samba*`, Syslog with `smbd` tag  
**Format:** Syslog with Samba logs

```
2026-06-20T16:45:22+00:00 myhost smbd[12345]: [2026/06/20 16:45:22.123] Connection denied from 192.168.1.1
2026-06-20T16:45:22+00:00 myhost smbd[12345]: [2026/06/20 16:45:22.123] Authentication failed for user user
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: error (for failures), info
- `source`: smbd
- `extra`: `{ip_address, user, share, operation}`

**Detects:** Authentication failures, access denied, share issues

---

### Container & Orchestration (2)

#### 36. Docker Parser
**Format Name:** `docker`  
**File Patterns:** `/var/lib/docker/containers/*/stdout*`, `/var/log/docker.log*`  
**Format:** JSON with container metadata

```json
{"log":"Out of memory: Kill process 1234 (app): score 100\n","stream":"stderr","time":"2026-06-20T16:45:22.123Z"}
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: Derived from log content
- `source`: docker
- `extra`: `{container_id, stream, message}`

**Detects:** Container crashes, OOM kills, resource exhaustion

---

#### 37. Kubernetes Parser
**Format Name:** `kubernetes`  
**File Patterns:** `/var/log/pods/*/containers/*/stdout*`, Kubelet logs  
**Format:** JSON with pod metadata

```json
{"log":"Error: Failed to pull image \"example.com/image:tag\"\n","stream":"stderr","time":"2026-06-20T16:45:22.123Z"}
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: Derived from log content
- `source`: kubernetes
- `extra`: `{namespace, pod, container, message}`

**Detects:** Pod failures, image pull errors, CrashLoopBackOff, evictions

---

### VPN & Network Security (1)

#### 38. OpenVPN Parser
**Format Name:** `openvpn`  
**File Patterns:** `/var/log/openvpn*`, Syslog with `openvpn` tag  
**Format:** Syslog with OpenVPN logs

```
2026-06-20T16:45:22+00:00 myhost ovpn-server[12345]: user/192.168.1.1:54321 Authenticate/Decrypt packet error: packet HMAC authentication failed
```

**Extracted Fields:**
- `timestamp`: 2026-06-20T16:45:22Z
- `severity`: warning (for errors), info
- `source`: openvpn
- `extra`: `{client, source_ip, operation, error_code}`

**Detects:** Authentication failures, tunnel drops, configuration issues

---

### Directory & Firewall (2)

#### 39. OpenLDAP (slapd) Parser
**Format Name:** `slapd`
**File Patterns:** `/var/log/slapd.log`, Syslog with `slapd` tag
**Format:** Syslog with OpenLDAP connection/operation records

```
Jun 20 10:23:46 dirhost slapd[1234]: conn=1002 op=0 RESULT tag=97 err=49 text=
```

**Extracted Fields:**
- `timestamp`, `severity` (err=49 / failures → warning, connection errors → error)
- `source`: slapd
- `extra`: `{conn, err, pid}`

**Detects:** Bind/auth failures (`err=49`), search limits, connection drops

#### 40. firewalld Parser
**Format Name:** `firewalld`
**File Patterns:** `/var/log/firewalld`, Syslog with `firewalld` tag
**Format:** Syslog with a leading level word (`INFO:`/`WARNING:`/`ERROR:`)

```
Jun 20 10:23:48 fwhost firewalld[1234]: ERROR: COMMAND_FAILED: '/usr/sbin/iptables ...' failed
```

**Extracted Fields:**
- `timestamp`, `severity` (from level word; `COMMAND_FAILED` → error)
- `source`: firewalld
- `extra`: `{pid}`

**Detects:** Rule application failures, zone/config warnings

---

### Infrastructure, HA & Coordination (4)

#### 41. keepalived Parser
**Format Name:** `keepalived`
**File Patterns:** Syslog with `Keepalived`/`Keepalived_vrrp`/`Keepalived_healthcheckers` tags
**Format:** Syslog VRRP / health-check records

```
Jun 20 10:23:49 lb1 Keepalived_vrrp[1234]: VRRP_Instance(VI_1) Entering FAULT STATE
```

**Extracted Fields:**
- `timestamp`, `severity` (FAULT / check failed → error, state transitions → warning)
- `source`: Keepalived*
- `extra`: `{vrrp_instance, pid}`

**Detects:** VRRP failovers, FAULT state, real-server health-check failures

#### 42. HashiCorp (Consul/Vault/Nomad) Parser
**Format Name:** `hashicorp`
**File Patterns:** `/var/log/{consul,vault,nomad}*`, hclog-format files
**Format:** `ISO-8601 [LEVEL] component: message`

```
2026-06-20T10:23:49.345Z [ERROR] core: failed to unseal: error="connection refused"
```

**Extracted Fields:**
- `timestamp`, `severity` (from `[LEVEL]`)
- `source`: component (agent/raft/core/vault/nomad/…)
- `extra`: `{component, level}`

**Detects:** No cluster leader, unseal failures, leadership/election churn

#### 43. etcd Parser
**Format Name:** `etcd`
**File Patterns:** `/var/log/etcd*`, zap-JSON logs
**Format:** One JSON object per line (`level`/`ts`/`caller`/`msg`)

```json
{"level":"warn","ts":"2026-06-20T10:23:46.456Z","caller":"etcdserver/util.go:163","msg":"apply request took too long","took":"200ms"}
```

**Extracted Fields:**
- `timestamp`, `severity` (from `level`)
- `source`: etcd
- `extra`: `{caller, took, error, …}`

**Detects:** Slow applies, deadline-exceeded, peer inactivity

#### 44. ZooKeeper Parser
**Format Name:** `zookeeper`
**File Patterns:** `/var/log/zookeeper/*.log`
**Format:** log4j (`ts [myid:N] - LEVEL [thread:Class@line] - msg`)

```
2026-06-20 10:23:48,012 [myid:1] - ERROR [main:QuorumPeer@1234] - Unexpected exception, exiting abnormally
```

**Extracted Fields:**
- `timestamp`, `severity` (from level)
- `source`: zookeeper
- `extra`: `{myid, thread, class}`

**Detects:** Leader/follower exceptions, fatal exits, snapshot pressure

---

### Reverse Proxies & Web (2)

#### 45. Traefik Parser
**Format Name:** `traefik`
**File Patterns:** Traefik JSON logs (zerolog)
**Format:** One JSON object per line (`level`/`msg`/`time`)

```json
{"level":"error","error":"dial tcp 10.0.0.7:8080: connect: connection refused","msg":"Error while creating client","time":"2026-06-20T10:23:48Z"}
```

**Extracted Fields:**
- `timestamp`, `severity` (from `level`)
- `source`: traefik
- `extra`: `{error, entryPointName, routerName, serviceName}`

**Detects:** Backend errors, upstream refused, configuration errors

#### 46. Caddy Parser
**Format Name:** `caddy`
**File Patterns:** Caddy v2 JSON logs (zap)
**Format:** One JSON object per line (`level`/`ts`/`logger`/`msg`)

```json
{"level":"error","ts":1718880227.789,"logger":"http.log.error","msg":"dial tcp: connection refused","request":{"method":"GET","uri":"/api"},"status":502}
```

**Extracted Fields:**
- `timestamp`, `severity` (from `level`; 5xx access lines elevated to error)
- `source`: caddy
- `extra`: `{logger, method, uri, status, error}`

**Detects:** 5xx access logs, no-upstreams, certificate failures

---

### Network, DNS & Disk Health (4)

#### 47. NetworkManager Parser
**Format Name:** `networkmanager`
**File Patterns:** Syslog with `NetworkManager` tag
**Format:** Syslog with an embedded `<info>`/`<warn>`/`<error>` marker

```
Jun 20 10:23:48 host NetworkManager[789]: <error> [1623.9] device (eth0): Activation: failed for connection 'Wired'
```

**Extracted Fields:**
- `timestamp`, `severity` (from marker; activation failures escalate)
- `source`: NetworkManager
- `extra`: `{pid}`

**Detects:** Activation failures, DHCP timeouts, carrier/link loss

#### 48. CoreDNS Parser
**Format Name:** `coredns`
**File Patterns:** CoreDNS container / file logs
**Format:** `[LEVEL] message` (optionally ISO-8601 prefixed), incl. query log

```
[ERROR] plugin/errors: 2 example.com. A: read udp 10.0.0.2:53->8.8.8.8:53: i/o timeout
```

**Extracted Fields:**
- `timestamp`, `severity` (from `[LEVEL]`)
- `source`: coredns
- `extra`: `{level, client, query_type, query_name}`

**Detects:** SERVFAIL, i/o timeouts, plugin/forward errors

#### 49. strongSwan (charon/IPsec) Parser
**Format Name:** `strongswan`
**File Patterns:** Syslog with `charon`/`ipsec`/`starter` tags
**Format:** Syslog with optional `NN[SUB]` thread/subsystem prefix

```
Jun 20 10:23:47 vpngw charon[1234]: 09[IKE] establishing IKE_SA failed, peer not responding
```

**Extracted Fields:**
- `timestamp`, `severity` (failures → error, retransmits/DPD → warning)
- `source`: charon/ipsec/starter
- `extra`: `{subsystem, pid}`

**Detects:** IKE_SA failures, retransmits, no-proposal, auth failures

#### 50. smartd (S.M.A.R.T.) Parser
**Format Name:** `smartd`
**File Patterns:** Syslog with `smartd` tag
**Format:** Syslog disk-health records

```
Jun 20 10:23:48 host smartd[1234]: Device: /dev/sdb [SAT], FAILED SMART self-check. BACK UP DATA NOW!
```

**Extracted Fields:**
- `timestamp`, `severity` (FAILED/self-test errors → error, pending sectors → warning)
- `source`: smartd
- `extra`: `{device, pid}`

**Detects:** Failing disks, pending/uncorrectable sectors, ATA errors

---

### Service Managers, Queues & Printing (3)

#### 51. supervisord Parser
**Format Name:** `supervisor`
**File Patterns:** `/var/log/supervisor/supervisord.log`
**Format:** `ts LEVEL message` (levels DEBG/INFO/WARN/ERRO/CRIT)

```
2026-06-20 10:23:50,678 INFO gave up: web entered FATAL state, too many start retries too quickly
```

**Extracted Fields:**
- `timestamp`, `severity` (FATAL/`gave up` escalate to error; CRIT → critical)
- `source`: supervisord
- `extra`: `{level}`

**Detects:** Crash loops, FATAL state, processes giving up

#### 52. Celery Parser
**Format Name:** `celery`
**File Patterns:** Celery worker logs
**Format:** `[ts: LEVEL/Process] message`

```
[2026-06-20 10:23:49,345: ERROR/ForkPoolWorker-3] Task app.tasks.div[def-456] raised unexpected: ZeroDivisionError
```

**Extracted Fields:**
- `timestamp`, `severity` (from level)
- `source`: celery
- `extra`: `{level, process, task, task_id}`

**Detects:** Task failures, WorkerLostError, broker disconnects

#### 53. CUPS Parser
**Format Name:** `cups`
**File Patterns:** `/var/log/cups/error_log`
**Format:** `LEVEL [DD/Mon/YYYY:HH:MM:SS +ZZZZ] message` (single-letter level)

```
E [20/Jun/2026:10:23:48 +0000] Unable to open listen socket for address [v1.::1]:631 - Address already in use
```

**Extracted Fields:**
- `timestamp`, `severity` (from level letter: E→error, W→warning, C/A→critical)
- `source`: cups
- `extra`: `{level}`

**Detects:** Print scheduler errors, listen-socket failures, job errors

---

### Fallback Parser (1)

#### 54. Generic Parser
**Format Name:** `generic`  
**File Patterns:** Any (last resort)  
**Format:** Unstructured text (attempts to parse any timestamp format)

```
Any log line that doesn't match a specific format
```

**Extracted Fields:**
- `timestamp`: Parsed if found; otherwise None
- `severity`: UNKNOWN
- `source`: Filename or "unknown"
- `extra`: Empty

**Use Case:** When no specific parser matches, shows all events but with minimal structure.

---

## Complete Parser Index

Every one of the 209 parsers, alphabetically, with its category and source file (`logcrux/parsers/`). This is the authoritative list — if a format isn't here, logcrux doesn't have a dedicated parser for it (it will fall to `generic`).

| Format name | Category | Source file |
|---|---|---|
| `activemq` | Message Queues | `logcrux/parsers/activemq.py` |
| `airflow` | Application Frameworks | `logcrux/parsers/airflow.py` |
| `alb` | Web Servers & Proxies | `logcrux/parsers/alb.py` |
| `ansible` | Other Daemons | `logcrux/parsers/ansible.py` |
| `apache-access` | Web Servers & Proxies | `logcrux/parsers/apache_access.py` |
| `apache-error` | Web Servers & Proxies | `logcrux/parsers/apache_error.py` |
| `apparmor` | System & Auth | `logcrux/parsers/apparmor.py` |
| `apthistory` | Build & Package Mgmt | `logcrux/parsers/apthistory.py` |
| `asterisk` | Linux Daemons | `logcrux/parsers/asterisk.py` |
| `auditd` | System & Auth | `logcrux/parsers/auditd.py` |
| `avahi` | Linux Daemons | `logcrux/parsers/avahi.py` |
| `azure` | Security / SIEM | `logcrux/parsers/azure.py` |
| `bazel` | Build & Package Mgmt | `logcrux/parsers/bazel.py` |
| `bluetoothd` | Linux Daemons | `logcrux/parsers/bluetoothd.py` |
| `bunyan` | Observability / Agents | `logcrux/parsers/bunyan.py` |
| `caddy` | Web Servers & Proxies | `logcrux/parsers/caddy.py` |
| `cassandra` | Databases | `logcrux/parsers/cassandra.py` |
| `cef` | Security / SIEM | `logcrux/parsers/cef.py` |
| `celery` | Other Daemons | `logcrux/parsers/celery.py` |
| `ceph` | Storage & Virtualization | `logcrux/parsers/ceph.py` |
| `certbot` | Other Daemons | `logcrux/parsers/certbot.py` |
| `chef` | Other Daemons | `logcrux/parsers/chef.py` |
| `chrony` | Linux Daemons | `logcrux/parsers/chrony.py` |
| `ciscoasa` | Security / SIEM | `logcrux/parsers/ciscoasa.py` |
| `clamav` | Other Daemons | `logcrux/parsers/clamav.py` |
| `clickhouse` | Databases | `logcrux/parsers/clickhouse.py` |
| `cloudflare` | Security / SIEM | `logcrux/parsers/cloudflare.py` |
| `cloudfront` | Web Servers & Proxies | `logcrux/parsers/cloudfront.py` |
| `cloudinit` | Containers & Cloud-Native | `logcrux/parsers/cloudinit.py` |
| `cloudtrail` | Containers & Cloud-Native | `logcrux/parsers/cloudtrail.py` |
| `cloudwatch` | Containers & Cloud-Native | `logcrux/parsers/cloudwatch.py` |
| `cockroachdb` | Databases | `logcrux/parsers/cockroachdb.py` |
| `composelog` | Containers & Cloud-Native | `logcrux/parsers/composelog.py` |
| `coredns` | Infrastructure, HA & DNS | `logcrux/parsers/coredns.py` |
| `cri` | Containers & Cloud-Native | `logcrux/parsers/cri.py` |
| `cron` | System & Auth | `logcrux/parsers/cron.py` |
| `cups` | Linux Daemons | `logcrux/parsers/cups.py` |
| `datadog` | Observability / Agents | `logcrux/parsers/datadog.py` |
| `dbus` | Linux Daemons | `logcrux/parsers/dbus.py` |
| `dhcpd` | Linux Daemons | `logcrux/parsers/dhcpd.py` |
| `django` | Application Frameworks | `logcrux/parsers/django.py` |
| `dnsmasq` | Infrastructure, HA & DNS | `logcrux/parsers/dnsmasq.py` |
| `docker` | Containers & Cloud-Native | `logcrux/parsers/docker.py` |
| `dovecot` | Mail | `logcrux/parsers/dovecot.py` |
| `dpkg` | Build & Package Mgmt | `logcrux/parsers/dpkg.py` |
| `druid` | Databases | `logcrux/parsers/druid.py` |
| `elasticsearch` | Databases | `logcrux/parsers/elasticsearch.py` |
| `envoy` | Web Servers & Proxies | `logcrux/parsers/envoy.py` |
| `etcd` | Infrastructure, HA & DNS | `logcrux/parsers/etcd.py` |
| `exim` | Mail | `logcrux/parsers/exim.py` |
| `fail2ban` | System & Auth | `logcrux/parsers/fail2ban.py` |
| `falco` | Security / SIEM | `logcrux/parsers/falco.py` |
| `filebeat` | Observability / Agents | `logcrux/parsers/filebeat.py` |
| `firewalld` | Infrastructure, HA & DNS | `logcrux/parsers/firewalld.py` |
| `flink` | Databases | `logcrux/parsers/flink.py` |
| `fluentbit` | Containers & Cloud-Native | `logcrux/parsers/fluentbit.py` |
| `fortigate` | Security / SIEM | `logcrux/parsers/fortigate.py` |
| `freeradius` | Infrastructure, HA & DNS | `logcrux/parsers/freeradius.py` |
| `frr` | Network / VPN | `logcrux/parsers/frr.py` |
| `ftp` | Linux Daemons | `logcrux/parsers/ftp.py` |
| `gcp` | Containers & Cloud-Native | `logcrux/parsers/gcp.py` |
| `gelf` | Security / SIEM | `logcrux/parsers/gelf.py` |
| `generic` | Fallback | `logcrux/parsers/generic.py` |
| `gitea` | Linux Daemons | `logcrux/parsers/gitea.py` |
| `githubactions` | Containers & Cloud-Native | `logcrux/parsers/githubactions.py` |
| `gitlab` | Containers & Cloud-Native | `logcrux/parsers/gitlab.py` |
| `glusterfs` | Storage & Virtualization | `logcrux/parsers/glusterfs.py` |
| `gostdlib` | Application Frameworks | `logcrux/parsers/gostdlib.py` |
| `gradle` | Build & Package Mgmt | `logcrux/parsers/gradle.py` |
| `gunicorn` | Application Frameworks | `logcrux/parsers/gunicorn.py` |
| `hadoop` | Big Data | `logcrux/parsers/hadoop.py` |
| `haproxy` | Web Servers & Proxies | `logcrux/parsers/haproxy.py` |
| `hashicorp` | Infrastructure, HA & DNS | `logcrux/parsers/hashicorp.py` |
| `hbase` | Databases | `logcrux/parsers/hbase.py` |
| `hive` | Databases | `logcrux/parsers/hive.py` |
| `iis` | Web Servers & Proxies | `logcrux/parsers/iis.py` |
| `jenkins` | Other Daemons | `logcrux/parsers/jenkins.py` |
| `jetty` | Application Frameworks | `logcrux/parsers/jetty.py` |
| `journald` | System & Auth | `logcrux/parsers/journald.py` |
| `json-access` | Web Servers & Proxies | `logcrux/parsers/json_access.py` |
| `jvmgc` | Big Data | `logcrux/parsers/jvmgc.py` |
| `kafka` | Message Queues | `logcrux/parsers/kafka.py` |
| `keepalived` | Infrastructure, HA & DNS | `logcrux/parsers/keepalived.py` |
| `kernel` | System & Auth | `logcrux/parsers/kernel.py` |
| `keycloak` | Infrastructure, HA & DNS | `logcrux/parsers/keycloak.py` |
| `kibana` | Observability / Agents | `logcrux/parsers/kibana.py` |
| `klog` | Containers & Cloud-Native | `logcrux/parsers/klog.py` |
| `klog-json` | Containers & Cloud-Native | `logcrux/parsers/klogjson.py` |
| `kong` | Web Servers & Proxies | `logcrux/parsers/kong.py` |
| `krb5kdc` | System & Auth | `logcrux/parsers/krb5kdc.py` |
| `kubeaudit` | Security / SIEM | `logcrux/parsers/kubeaudit.py` |
| `kubernetes` | Containers & Cloud-Native | `logcrux/parsers/kubernetes.py` |
| `laravel` | Application Frameworks | `logcrux/parsers/laravel.py` |
| `leef` | Security / SIEM | `logcrux/parsers/leef.py` |
| `libvirt` | Storage & Virtualization | `logcrux/parsers/libvirt.py` |
| `lighttpd` | Web Servers & Proxies | `logcrux/parsers/lighttpd.py` |
| `log4j` | Application Frameworks | `logcrux/parsers/log4j.py` |
| `logfmt` | Observability / Agents | `logcrux/parsers/logfmt.py` |
| `logrus` | Observability / Agents | `logcrux/parsers/logrus.py` |
| `logstash` | Observability / Agents | `logcrux/parsers/logstash.py` |
| `lxc` | Storage & Virtualization | `logcrux/parsers/lxc.py` |
| `maven` | Build & Package Mgmt | `logcrux/parsers/maven.py` |
| `mdadm` | Storage & Virtualization | `logcrux/parsers/mdadm.py` |
| `mikrotik` | Network / VPN | `logcrux/parsers/mikrotik.py` |
| `minio` | Storage & Virtualization | `logcrux/parsers/minio.py` |
| `modsecurity` | Security / SIEM | `logcrux/parsers/modsecurity.py` |
| `mongodb` | Databases | `logcrux/parsers/mongodb.py` |
| `monit` | Observability / Agents | `logcrux/parsers/monit.py` |
| `mosquitto` | Message Queues | `logcrux/parsers/mosquitto.py` |
| `mssql` | Databases | `logcrux/parsers/mssql.py` |
| `mysql` | Databases | `logcrux/parsers/mysql.py` |
| `nagios` | Observability / Agents | `logcrux/parsers/nagios.py` |
| `named` | Infrastructure, HA & DNS | `logcrux/parsers/named.py` |
| `nats` | Message Queues | `logcrux/parsers/nats.py` |
| `neo4j` | Databases | `logcrux/parsers/neo4j.py` |
| `networkmanager` | Infrastructure, HA & DNS | `logcrux/parsers/networkmanager.py` |
| `nextcloud` | Linux Daemons | `logcrux/parsers/nextcloud.py` |
| `nginx-access` | Web Servers & Proxies | `logcrux/parsers/nginx_access.py` |
| `nginx-error` | Web Servers & Proxies | `logcrux/parsers/nginx_error.py` |
| `npm` | Build & Package Mgmt | `logcrux/parsers/npm.py` |
| `okta` | Security / SIEM | `logcrux/parsers/okta.py` |
| `opendkim` | Mail | `logcrux/parsers/opendkim.py` |
| `opensmtpd` | Mail | `logcrux/parsers/opensmtpd.py` |
| `openvpn` | Network / VPN | `logcrux/parsers/openvpn.py` |
| `oracle` | Databases | `logcrux/parsers/oracle.py` |
| `osquery` | Security / SIEM | `logcrux/parsers/osquery.py` |
| `otel` | Observability / Agents | `logcrux/parsers/otel.py` |
| `otlp` | Containers & Cloud-Native | `logcrux/parsers/otlp.py` |
| `paloalto` | Security / SIEM | `logcrux/parsers/paloalto.py` |
| `patroni` | Infrastructure, HA & DNS | `logcrux/parsers/patroni.py` |
| `pfsense` | Security / SIEM | `logcrux/parsers/pfsense.py` |
| `pgbouncer` | Databases | `logcrux/parsers/pgbouncer.py` |
| `phoenix` | Application Frameworks | `logcrux/parsers/phoenix.py` |
| `php-fpm` | Application Frameworks | `logcrux/parsers/phpfpm.py` |
| `phperror` | Application Frameworks | `logcrux/parsers/phperror.py` |
| `pihole` | Network / VPN | `logcrux/parsers/pihole.py` |
| `pingaccess` | Identity & Access Mgmt | `logcrux/parsers/pingaccess.py` |
| `pingauthorize` | Identity & Access Mgmt | `logcrux/parsers/pingauthorize.py` |
| `pingdirectory` | Identity & Access Mgmt | `logcrux/parsers/pingdirectory.py` |
| `pingfederate` | Identity & Access Mgmt | `logcrux/parsers/pingfederate.py` |
| `pingintelligence` | Identity & Access Mgmt | `logcrux/parsers/pingintelligence.py` |
| `pino` | Observability / Agents | `logcrux/parsers/pino.py` |
| `pip` | Build & Package Mgmt | `logcrux/parsers/pip.py` |
| `podman` | Storage & Virtualization | `logcrux/parsers/podman.py` |
| `polkit` | Linux Daemons | `logcrux/parsers/polkit.py` |
| `postfix` | Mail | `logcrux/parsers/postfix.py` |
| `postgresql` | Databases | `logcrux/parsers/postgresql.py` |
| `powerdns` | Infrastructure, HA & DNS | `logcrux/parsers/powerdns.py` |
| `pulsar` | Message Queues | `logcrux/parsers/pulsar.py` |
| `puma` | Application Frameworks | `logcrux/parsers/puma.py` |
| `puppet` | Other Daemons | `logcrux/parsers/puppet.py` |
| `pylogging` | Observability / Agents | `logcrux/parsers/pylogging.py` |
| `qemu` | Storage & Virtualization | `logcrux/parsers/qemu.py` |
| `rabbitmq` | Message Queues | `logcrux/parsers/rabbitmq.py` |
| `rails` | Application Frameworks | `logcrux/parsers/rails.py` |
| `redis` | Databases | `logcrux/parsers/redis.py` |
| `rspamd` | Mail | `logcrux/parsers/rspamd.py` |
| `rsyncd` | Other Daemons | `logcrux/parsers/rsyncd.py` |
| `rsyslog` | Linux Daemons | `logcrux/parsers/rsyslog.py` |
| `s3access` | Containers & Cloud-Native | `logcrux/parsers/s3access.py` |
| `saltstack` | Other Daemons | `logcrux/parsers/saltstack.py` |
| `samba` | Linux Daemons | `logcrux/parsers/samba.py` |
| `secure` | System & Auth | `logcrux/parsers/secure.py` |
| `sendmail` | Mail | `logcrux/parsers/sendmail.py` |
| `serilog` | Observability / Agents | `logcrux/parsers/serilog.py` |
| `sidekiq` | Application Frameworks | `logcrux/parsers/sidekiq.py` |
| `slapd` | Infrastructure, HA & DNS | `logcrux/parsers/slapd.py` |
| `smartd` | Infrastructure, HA & DNS | `logcrux/parsers/smartd.py` |
| `snapd` | Linux Daemons | `logcrux/parsers/snapd.py` |
| `snort` | Security / SIEM | `logcrux/parsers/snort.py` |
| `solr` | Big Data | `logcrux/parsers/solr.py` |
| `spamassassin` | Mail | `logcrux/parsers/spamassassin.py` |
| `spark` | Big Data | `logcrux/parsers/spark.py` |
| `springboot` | Application Frameworks | `logcrux/parsers/springboot.py` |
| `squid` | Web Servers & Proxies | `logcrux/parsers/squid.py` |
| `sssd` | System & Auth | `logcrux/parsers/sssd.py` |
| `strongswan` | Infrastructure, HA & DNS | `logcrux/parsers/strongswan.py` |
| `sudo` | System & Auth | `logcrux/parsers/sudo.py` |
| `supervisor` | Other Daemons | `logcrux/parsers/supervisor.py` |
| `suricata` | Security / SIEM | `logcrux/parsers/suricata.py` |
| `syslog` | System & Auth | `logcrux/parsers/syslog.py` |
| `syslogng` | Linux Daemons | `logcrux/parsers/syslogng.py` |
| `tailscale` | Network / VPN | `logcrux/parsers/tailscale.py` |
| `telegraf` | Observability / Agents | `logcrux/parsers/telegraf.py` |
| `terraform` | Containers & Cloud-Native | `logcrux/parsers/terraform.py` |
| `tomcat` | Application Frameworks | `logcrux/parsers/tomcat.py` |
| `traefik` | Web Servers & Proxies | `logcrux/parsers/traefik.py` |
| `trino` | Databases | `logcrux/parsers/trino.py` |
| `ufw` | System & Auth | `logcrux/parsers/ufw.py` |
| `unbound` | Infrastructure, HA & DNS | `logcrux/parsers/unbound.py` |
| `unifi` | Network / VPN | `logcrux/parsers/unifi.py` |
| `uvicorn` | Application Frameworks | `logcrux/parsers/uvicorn.py` |
| `uwsgi` | Application Frameworks | `logcrux/parsers/uwsgi.py` |
| `vaultaudit` | Security / SIEM | `logcrux/parsers/vaultaudit.py` |
| `vmware` | Storage & Virtualization | `logcrux/parsers/vmware.py` |
| `vpcflow` | Containers & Cloud-Native | `logcrux/parsers/vpcflow.py` |
| `vsftpd` | Linux Daemons | `logcrux/parsers/vsftpd.py` |
| `wazuh` | Security / SIEM | `logcrux/parsers/wazuh.py` |
| `werkzeug` | Web Servers & Proxies | `logcrux/parsers/werkzeug.py` |
| `wildfly` | Application Frameworks | `logcrux/parsers/wildfly.py` |
| `winston` | Observability / Agents | `logcrux/parsers/winston.py` |
| `wireguard` | Network / VPN | `logcrux/parsers/wireguard.py` |
| `wpa_supplicant` | Network / VPN | `logcrux/parsers/wpa_supplicant.py` |
| `xorg` | Other Daemons | `logcrux/parsers/xorg.py` |
| `yum` | Build & Package Mgmt | `logcrux/parsers/yum.py` |
| `zabbix` | Observability / Agents | `logcrux/parsers/zabbix.py` |
| `zeek` | Security / SIEM | `logcrux/parsers/zeek.py` |
| `zfs` | Storage & Virtualization | `logcrux/parsers/zfs.py` |
| `zookeeper` | Infrastructure, HA & DNS | `logcrux/parsers/zookeeper.py` |

---

## Parser Selection Algorithm

logcrux selects a parser using this algorithm:

1. **Path-based hints** (most specific)
   - `/var/log/auth.log` → SecureParser
   - `/var/log/kubernetes*` → KubernetesParser
   - `/var/log/docker/*` → DockerParser

2. **Sample analysis** (if path doesn't uniquely identify)
   - Check first 10-100 lines
   - Call `Parser.can_parse(path, sample_lines)` on each parser in order
   - Use first that returns True

3. **Parser order** (specificity)
   - Path-specific checks first (K8s, Docker, journald)
   - Format-specific checks (Nginx error, Apache error)
   - Proxy checks (HAProxy, Squid)
   - Web access checks (Nginx, Apache)
   - Security checks (auditd, UFW, fail2ban)
   - Syslog-tagged services (sudo, cron, dhcp, named, dovecot, samba, chrony, vsftpd, dnsmasq)
   - Structured logs (MongoDB, Elasticsearch, Kafka, etc.)
   - Database logs (MySQL, PostgreSQL, Redis)
   - Mail/FTP (Postfix, Dovecot, Exim, FTP)
   - System catch-alls (syslog, generic)

4. **Fallback**
   - If nothing matches, use GenericParser

## Detection Precision

Each parser's `can_parse()` method uses distinctive markers:

- **Nginx error:** `"error"` severity tag + PID#TID pattern
- **Apache error:** `[error:module]` or `[crit]` patterns
- **PostgreSQL:** `"user@database"` pattern + `[PID]` + severity
- **MongoDB:** `"$date"` in JSON or specific log format
- **HAProxy:** `"haproxy["` prefix or CLF with special fields
- **Squid:** Access format with `TCP_HIT`/`TCP_MISS` or cache.log format

This ensures **no false positives** — a syslog line tagged with `[kernel]` won't match a web server parser.

---

**Last Updated:** July 2026
