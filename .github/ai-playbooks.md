# AI Playbooks

## Playbook 1: Issue Triage

### Input
- Bug report or operational alert
- May contain: logs, symptoms, affected services, timestamp

### Triage Steps

```
Step 1: CLASSIFY SUBSYSTEM
─────────────────────────
Keywords → Subsystem:
  "syscfg" / "config" / "nvram" / "persist"     → syscfg
  "sysevent" / "event" / "trigger" / "callback"  → sysevent
  "iptables" / "firewall" / "blocked" / "NAT"    → firewall
  "dhcp" / "dnsmasq" / "lease" / "pool"          → service_dhcp
  "wan" / "udhcpc" / "internet" / "erouter"      → service_wan
  "ipv6" / "prefix" / "dibbler" / "radvd"        → service_ipv6
  "bridge" / "vlan" / "brlan" / "multinet"       → service_multinet
  "route" / "zebra" / "rip" / "default gw"       → service_routed
  "ddns" / "dynamic dns" / "dyndns"              → service_ddns
  "process" / "crash" / "restart" / "pmon"        → process_health

Step 2: ASSESS SEVERITY
────────────────────────
  P1 (Critical): System unresponsive, syseventd down, all services failed
  P2 (High): WAN down, no internet, major service (DHCP/FW) failed
  P3 (Medium): Single feature broken (DDNS, IPv6, port forward)
  P4 (Low): Cosmetic, logging issue, non-functional regression

Step 3: IDENTIFY FIRST DEBUG ACTION
────────────────────────────────────
  syscfg issues    → syscfg show; ipcs -m
  sysevent issues  → ps | grep syseventd; cat sysevent_tracer.txt
  firewall issues  → sysevent get firewall-status; cat /tmp/.ipt
  DHCP issues      → ps | grep dnsmasq; sysevent get dhcp_server-status
  WAN issues       → sysevent get wan-status; sysevent get current_wan_ipaddr
  IPv6 issues      → sysevent get tr_erouter0_dhcpv6_client_v6pref
  Multinet issues  → brctl show; sysevent get multinet_N-status
  Routing issues   → ip route show; ps | grep zebra

Step 4: OUTPUT
──────────────
  → Subsystem: [identified]
  → Severity: [P1-P4]
  → Immediate action: [first debug command]
  → Escalation path: [if P1/P2, who owns this]
```

---

## Playbook 2: Log Analysis

### Input
- Log file content (Consolelog.txt, FirewallDebug.txt, sysevent_tracer.txt, SelfHeal.txt)

### Analysis Steps

```
Step 1: IDENTIFY LOG SOURCE
────────────────────────────
  /rdklogs/logs/Consolelog.txt.0      → Service operations (DHCP, WAN, routing)
  /rdklogs/logs/FirewallDebug.txt     → Firewall rule generation
  /rdklogs/logs/sysevent_tracer.txt   → Event flow tracing
  /rdklogs/logs/MnetDebug.txt         → MultiNet/bridge operations
  /rdklogs/logs/SelfHeal.txt.0        → Process crash/restart events
  /var/log/messages                   → Kernel + syslog (ulog output)

Step 2: EXTRACT SIGNALS
────────────────────────
  Error patterns to look for:
    "failed"          → Operation failure (note what failed)
    "errno"           → System error (decode errno value)
    "segfault"        → Memory corruption / NULL deref
    "timeout"         → IPC or network timeout
    "EOWNERDEAD"      → Mutex holder crashed (usually auto-recovered)
    "killed"          → Process killed (OOM? sanity thread?)
    "ENOSPC"          → Filesystem full
    "connection refused" → Daemon not running (syseventd? dbus?)

Step 3: CONSTRUCT TIMELINE
──────────────────────────
  - Sort events by timestamp
  - Identify first error (root) vs cascading errors (effects)
  - Map event names to services
  - Identify state transitions (starting→error, started→stopping)

Step 4: CORRELATE WITH KNOWN PATTERNS
──────────────────────────────────────
  See Knowledge Base (ai-knowledge-base.md) for known failure signatures.

Step 5: OUTPUT
──────────────
  → Timeline: [ordered events with timestamps]
  → Root event: [first anomaly]
  → Cascade: [subsequent failures caused by root]
  → Confidence: [high/medium/low]
  → Next steps: [verification commands]
```

---

## Playbook 3: Recovery Procedures

### By Subsystem

#### Syscfg Recovery
```
Symptom: Configuration reads returning garbage or errors
Level 1: syscfg commit  (force write to file)
Level 2: syscfg destroy; syscfg_create -f /nvram/syscfg.db  (recreate shm)
Level 3: cp /nvram/syscfg.db.prev /nvram/syscfg.db; reboot  (restore backup)
Level 4: rm /nvram/syscfg.db*; reboot  (factory reset - loads system_defaults)
```

#### Sysevent Recovery
```
Symptom: Events not delivered, services not responding
Level 1: Restart individual service (sysevent set <service>-restart)
Level 2: Check PID file and worker threads
Level 3: kill syseventd; /usr/bin/syseventd --threads 10  (restart bus)
Level 4: Reboot (full system restart)
```

#### Firewall Recovery
```
Symptom: Traffic blocked/incorrect filtering
Level 1: sysevent set firewall-restart  (regenerate and reapply)
Level 2: rm /tmp/firewall_mutex; sysevent set firewall-restart  (clear stuck mutex)
Level 3: iptables -F; iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT  (emergency allow-all)
Level 4: syscfg set firewall_level low; sysevent set firewall-restart  (reduce ruleset)
```

#### DHCP Recovery
```
Symptom: LAN clients not getting IPs
Level 1: sysevent set dhcp_server-restart
Level 2: killall dnsmasq; sysevent set dhcp_server-start
Level 3: sysevent set dhcp_server-status stopped; sysevent set dhcp_server-start  (reset state machine)
Level 4: Check/regenerate /etc/dnsmasq.conf manually
```

#### WAN Recovery
```
Symptom: No internet connectivity
Level 1: sysevent set wan-restart
Level 2: kill udhcpc; sysevent set wan-start  (restart DHCP client)
Level 3: ifconfig erouter0 down; sleep 2; ifconfig erouter0 up; sysevent set wan-start
Level 4: Check physical link: cat /sys/class/net/erouter0/carrier
```

---

## Playbook 4: Performance Investigation

### Input
- Slow system response, event processing delays, high CPU

### Steps

```
Step 1: IDENTIFY BOTTLENECK
────────────────────────────
  CPU: top -b -n 1 | head -20
  Memory: free -m; cat /proc/meminfo
  Disk I/O: iostat (if available); df /nvram; df /tmp
  FD usage: ls /proc/<syseventd_pid>/fd | wc -l
  
Step 2: CHECK SYSEVENT HEALTH
──────────────────────────────
  Workers blocked: grep "BLOCKED" /rdklogs/logs/sysevent_tracer.txt
  Event queue depth: (no direct metric — infer from processing delays)
  Client count: count unique client connections

Step 3: CHECK SYSCFG CONTENTION
────────────────────────────────
  Lock contention: strace -e futex syscfg get <key>
  Commit frequency: grep "commit" /rdklogs/logs/Consolelog.txt.0 | tail
  File size: ls -la /nvram/syscfg.db

Step 4: CHECK FIREWALL
───────────────────────
  Rule count: iptables -L -n | wc -l
  Conntrack: cat /proc/net/nf_conntrack | wc -l
  Rebuild time: time sysevent set firewall-restart

Step 5: REMEDIATION
───────────────────
  - Reduce firewall rule complexity
  - Batch syscfg commits (don't commit per-key)
  - Kill orphaned sysevent clients
  - Increase worker thread count if event queue growing
```
