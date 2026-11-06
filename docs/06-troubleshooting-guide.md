# Troubleshooting Guide

## 1. Sysevent Bus Failures

### 1.1 Sysevent Daemon Not Starting

**Symptom:** All services fail to register. Events not delivered. System stuck in early boot.

**Logs:**
```
/var/log/messages: UTOPIA: syseventd: could not create PID file
/var/log/messages: UTOPIA: syseventd: another instance already running
```

**Root Cause:** PID file stale from previous crash, or filesystem full.

**Debug Steps:**
1. `cat /var/run/syseventd.pid` — check if PID is valid
2. `ls -la /proc/<pid>/` — verify process exists
3. `df /var/run/` — check filesystem space
4. `cat /proc/sys/kernel/threads-max` — check thread limits

**Resolution:**
```bash
rm -f /var/run/syseventd.pid
/usr/bin/syseventd --threads 10
```

### 1.2 Events Not Being Delivered

**Symptom:** Service callbacks not firing. Configuration changes have no effect.

**Logs:**
```
/rdklogs/logs/sysevent_tracer.txt: [timestamp] EVENT SET: <name> = <value>
# Missing corresponding: ACTION EXEC: <handler>
```

**Root Cause:** Trigger registration lost (client disconnected), or worker threads blocked.

**Debug Steps:**
1. `sysevent get <event_name>` — verify event was set
2. Check `/tmp/syseventd_worker_*` FIFOs exist
3. `ls /proc/<syseventd_pid>/task/` — count active threads
4. `cat /rdklogs/logs/sysevent_tracer.txt | grep BLOCKED` — check for blocked actions

**Resolution:**
- Restart affected service (re-registers callbacks)
- If all workers blocked: `kill -TERM <syseventd_pid>` and restart syseventd

### 1.3 Client Connection Exhaustion

**Symptom:** New services cannot connect to sysevent. Error: "connection refused."

**Root Cause:** Client table full or FD limit reached.

**Debug Steps:**
1. `ls /proc/<syseventd_pid>/fd | wc -l` — count open FDs
2. `ulimit -n` — check FD limit
3. Check for leaked connections (orphaned service processes)

**Resolution:**
- Kill orphaned service processes
- Increase FD limit in syseventd startup
- Restart syseventd to reset client table

---

## 2. Syscfg Configuration Issues

### 2.1 Configuration Not Persisting Across Reboot

**Symptom:** Settings revert to defaults after reboot. Changes made via CLI or API are lost.

**Logs:**
```
UTOPIA: syscfg: commit failed, errno=28 (ENOSPC)
UTOPIA: syscfg: WARNING - loading from backup file
```

**Root Cause:** `/nvram` partition full, preventing commit. Or file corruption.

**Debug Steps:**
1. `df /nvram/` — check partition space
2. `ls -la /nvram/syscfg.db*` — check file sizes and timestamps
3. `syscfg show | wc -l` — count total entries (expect ~200-500)
4. Check for stuck commit lock: look for processes holding semaphore

**Resolution:**
```bash
# Clear nvram space
rm -f /nvram/*.log /nvram/core.*
# Force commit
syscfg commit
# Verify
syscfg get lan_ipaddr
```

### 2.2 Shared Memory Corruption

**Symptom:** Services crash with SIGSEGV when reading syscfg. Random garbage values returned.

**Logs:**
```
kernel: service_dhcp[1234]: segfault at <addr> ip <ip> sp <sp>
```

**Root Cause:** Process crashed while holding write lock, corrupting hash table linkage.

**Debug Steps:**
1. `ipcs -m` — list shared memory segments, check for orphaned
2. `syscfg show 2>&1 | grep -i error` — look for read errors
3. `syscfg get <known_key>` — test basic retrieval
4. `_syscfg_find_corrupted_keys` function detects bad entries

**Resolution:**
```bash
# Nuclear option: recreate from file
syscfg destroy
syscfg_create -f /nvram/syscfg.db
# Or factory reset if file also corrupt
```

### 2.3 EOWNERDEAD Lock Recovery

**Symptom:** First syscfg operation after process crash returns error, then succeeds on retry.

**Logs:**
```
UTOPIA: syscfg: mutex EOWNERDEAD, recovering
```

**Root Cause:** Previous process died while holding mutex. Robust mutex protocol recovers automatically.

**Debug Steps:** Usually self-healing. Monitor for:
1. Frequent EOWNERDEAD messages (indicates chronic crasher)
2. Identify crashing process via `/var/log/messages` coredump entries

**Resolution:** Fix the crashing process. The lock recovery is automatic.

---

## 3. Firewall Issues

### 3.1 All Traffic Blocked After Firewall Restart

**Symptom:** No internet access. LAN clients cannot reach WAN. Ping from router fails.

**Logs:**
```
/rdklogs/logs/FirewallDebug.txt: iptables-restore: line N failed
UTOPIA: firewall: iptables-restore returned non-zero
```

**Root Cause:** Syntax error in generated rule file. Typically due to empty/null WAN IP or invalid port range from misconfigured port forwarding.

**Debug Steps:**
1. `cat /tmp/.ipt | head -50` — examine generated rules
2. `iptables-restore --test < /tmp/.ipt` — validate without applying
3. `sysevent get current_wan_ipaddr` — check if WAN IP is set
4. `iptables -L -n --line-numbers` — see current active rules
5. `grep -n "^-" /tmp/.ipt | grep "0.0.0.0"` — find rules with empty IPs

**Resolution:**
```bash
# Emergency: allow all traffic
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
# Then fix the bad syscfg entry and restart
sysevent set firewall-restart
```

### 3.2 Firewall Mutex Deadlock

**Symptom:** Firewall restart hangs indefinitely. `firewall-status` stays at "starting."

**Logs:**
```
/rdklogs/logs/FirewallDebug.txt: acquiring mutex...
# No "mutex acquired" follow-up
```

**Root Cause:** Previous firewall process crashed while holding shared mutex. EOWNERDEAD not triggered (rare kernel bug).

**Debug Steps:**
1. `ls -la /tmp/firewall_mutex` — check mutex file exists
2. `fuser /tmp/firewall_mutex` — check who holds it
3. `ps aux | grep firewall` — look for zombie firewall processes

**Resolution:**
```bash
# Remove stale mutex, kill zombies
rm -f /tmp/firewall_mutex
killall -9 firewall
sysevent set firewall-restart
```

### 3.3 Port Forwarding Not Working

**Symptom:** External clients cannot reach forwarded port. Service accessible from LAN.

**Debug Steps:**
1. `iptables -t nat -L prerouting_fromwan -n` — check DNAT rules exist
2. `iptables -L FORWARD -n | grep <internal_ip>` — check forward rule
3. `syscfg get SinglePortForwardCount` — verify config present
4. `sysevent get current_wan_ipaddr` — WAN IP must be non-empty
5. `conntrack -L | grep <port>` — check for stale conntrack entries

**Resolution:**
```bash
conntrack -F
sysevent set firewall-restart
```

---

## 4. DHCP Service Issues

### 4.1 LAN Clients Not Getting IP Addresses

**Symptom:** Devices connect to WiFi/Ethernet but get 169.254.x.x (link-local) address.

**Logs:**
```
/rdklogs/logs/Consolelog.txt.0: [service_dhcp] dhcp_server_start: dnsmasq failed to start
/var/log/messages: dnsmasq: failed to bind DHCP server socket: Address already in use
```

**Root Cause:** dnsmasq not running, port conflict, or wrong interface binding.

**Debug Steps:**
1. `ps | grep dnsmasq` — check if running
2. `cat /var/run/dnsmasq.pid` — verify PID file
3. `netstat -ulnp | grep :67` — check port 67 binding
4. `cat /etc/dnsmasq.conf | grep interface` — verify correct bridge
5. `sysevent get dhcp_server-status` — check service state
6. `brctl show` — verify bridge exists and has members

**Resolution:**
```bash
killall dnsmasq
sysevent set dhcp_server-restart
```

### 4.2 DHCP Server Stuck in "starting" State

**Symptom:** `sysevent get dhcp_server-status` returns "starting" indefinitely.

**Root Cause:** Previous start/stop operation interrupted (process killed during transition).

**Debug Steps:**
1. `sysevent get dhcp_server-status` — confirm stuck state
2. `ps | grep service_dhcp` — check for running handler
3. `ps | grep dnsmasq` — check if dnsmasq actually running

**Resolution:**
```bash
sysevent set dhcp_server-status stopped
sysevent set dhcp_server-restart
```

---

## 5. WAN Connectivity Issues

### 5.1 WAN Interface Not Getting IP

**Symptom:** No internet. `sysevent get current_wan_ipaddr` returns empty.

**Logs:**
```
/rdklogs/logs/Consolelog.txt.0: [service_wan] udhcpc start failed
/var/log/messages: udhcpc: sending discover... (repeated)
```

**Root Cause:** WAN physical link down, DHCP server unresponsive, or interface misconfigured.

**Debug Steps:**
1. `cat /sys/class/net/erouter0/carrier` — check physical link (1=up)
2. `ifconfig erouter0` — verify interface is UP
3. `ps | grep udhcpc` — check DHCP client running
4. `cat /var/run/udhcpc.erouter0.pid` — verify PID file
5. `sysevent get wan-status` — check WAN state
6. `syscfg get wan_proto` — verify expected protocol

**Resolution:**
```bash
# Restart WAN service
sysevent set wan-restart
# Or manually restart DHCP client
kill $(cat /var/run/udhcpc.erouter0.pid)
sysevent set wan-start
```

### 5.2 WAN IP Acquired But No Internet

**Symptom:** WAN IP present but cannot reach external servers. Ping to 8.8.8.8 fails.

**Debug Steps:**
1. `ip route show` — verify default route exists
2. `ip route get 8.8.8.8` — check routing decision
3. `iptables -L FORWARD -n -v` — check for blocked forwarding
4. `cat /etc/resolv.conf` — verify DNS configured
5. `sysevent get default_router` — check gateway set
6. `arping -I erouter0 <gateway>` — verify gateway reachable at L2

**Resolution:**
```bash
# Add default route manually
ip route add default via <gateway_ip> dev erouter0
# Restart firewall (may be blocking)
sysevent set firewall-restart
```

---

## 6. IPv6 Issues

### 6.1 No IPv6 Prefix Delegation

**Symptom:** LAN clients get no IPv6 global address. Only link-local (fe80::).

**Logs:**
```
/rdklogs/logs/Consolelog.txt.0: [service_ipv6] no valid prefix from DHCPv6 client
```

**Debug Steps:**
1. `sysevent get tr_erouter0_dhcpv6_client_v6pref` — check prefix received
2. `ps | grep dibbler` — check DHCPv6 client running
3. `cat /tmp/.dibbler-info/client_received_options` — raw DHCPv6 data
4. `ip -6 addr show brlan0` — check LAN bridge IPv6 addresses
5. `ps | grep radvd` — check router advertisement daemon

**Resolution:**
```bash
sysevent set service_ipv6-restart
# Or restart DHCPv6 client
killall dibbler-client
sysevent set wan-restart  # Triggers DHCPv6 re-negotiation
```

---

## 7. Multi-Network / Bridge Issues

### 7.1 Bridge Not Created

**Symptom:** `brctl show` doesn't list expected bridge. Associated services fail.

**Logs:**
```
/rdklogs/logs/MnetDebug.txt: multinet_bridgeUpInst: failed to create bridge brlan1
```

**Debug Steps:**
1. `brctl show` — list existing bridges
2. `sysevent get multinet_1-status` — check instance status
3. Check interface availability: `ip link show`
4. Verify PSM config: multinet instance definitions

**Resolution:**
```bash
sysevent set multinet_1-up
# Or manually
brctl addbr brlan1
ifconfig brlan1 up
```

---

## 8. Process Monitor (pmon) Issues

### 8.1 Service Not Being Auto-Restarted

**Symptom:** Process crashed but pmon doesn't restart it.

**Debug Steps:**
1. Check pmon config file for the process entry
2. Verify PID file path matches pmon config
3. `cat <pidfile>` — confirm PID file is stale
4. Check pmon cron job: `crontab -l | grep pmon`
5. Verify executable path in restart command exists

**Resolution:** Add/fix entry in pmon configuration file:
```
<process_name> <pid_file> <restart_command>
```

---

## Diagnostic Command Reference

| Command | Purpose |
|---|---|
| `sysevent get <key>` | Read runtime event/state value |
| `sysevent set <key> <value>` | Set event (trigger handlers) |
| `syscfg get <key>` | Read persistent configuration |
| `syscfg set <key> <value>; syscfg commit` | Write persistent config |
| `syscfg show` | Dump all configuration |
| `iptables -L -n -v` | List active firewall rules with counters |
| `ip route show` | Display routing table |
| `ip -6 route show` | Display IPv6 routing table |
| `brctl show` | List bridges and members |
| `cat /proc/net/nf_conntrack` | Active connection tracking entries |
| `ps | grep -E "syseventd|dnsmasq|udhcpc|dibbler|zebra"` | Check service processes |
| `cat /rdklogs/logs/Consolelog.txt.0` | Main console log |
| `cat /rdklogs/logs/FirewallDebug.txt` | Firewall-specific debug |
| `cat /rdklogs/logs/MnetDebug.txt` | MultiNet debug log |
| `cat /rdklogs/logs/sysevent_tracer.txt` | Event trace log |
| `ipcs -m` | Shared memory segments (syscfg) |
