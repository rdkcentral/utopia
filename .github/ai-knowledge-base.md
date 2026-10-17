# AI Knowledge Base — Utopia

## Signal Dictionary

| Signal | Source | Meaning | Action |
|--------|--------|---------|--------|
| `wan-status = started` | service_wan/service_udhcpc | WAN IP acquired, internet reachable | Triggers: firewall-restart, routing, DDNS, IPv6 |
| `wan-status = stopped` | service_wan | WAN connection lost | Triggers: service cleanup, LED change |
| `dhcp_server-status = started` | service_dhcp | dnsmasq running, serving leases | LAN clients can get IPs |
| `dhcp_server-status = error` | service_dhcp | dnsmasq failed to start | Check port conflict, config syntax |
| `firewall-status = started` | firewall | Rules applied successfully | Traffic filtering active |
| `firewall-status = error` | firewall | iptables-restore failed | Check /tmp/.ipt for syntax errors |
| `system-status = started` | init scripts | Full system initialization complete | All services should be registered |
| `multinet_N-status = ready` | service_multinet | Bridge N created and configured | Dependent services can bind |
| `current_wan_ipaddr = <IP>` | service_udhcpc | Current WAN IPv4 address | Used by firewall, NAT, DDNS |
| `lan-status = started` | service_dhcp | LAN interface ready | DHCP, DNS can serve |
| `ipv4_N-status = up` | service_dhcp | IPv4 instance N configured | Interface has IP, ready for traffic |
| `bridge_mode = 1` | syscfg | Device in bridge mode | Most services disabled, passthrough |

## Error Code Reference

### Syscfg Errors
| Code | Constant | Meaning | Fix |
|------|----------|---------|-----|
| -1 | ERR_INVALID_PARAM | NULL key or buffer | Check caller code |
| -2 | ERR_IO_FAILURE | File read/write failed | Check /nvram space |
| -3 | ERR_SHM_CREATE | shmget/shmat failed | Check SHMMAX kernel param |
| -4 | ERR_MEM_ALLOC | malloc failed | System OOM |
| -5 | ERR_SEMAPHORE_INIT | Mutex init failed | Shared memory corrupt |

### Sysevent Client Errors
| Code | Constant | Meaning | Fix |
|------|----------|---------|-----|
| -1 | ERR_NOT_INITED | Client table not initialized | Restart syseventd |
| -2 | ERR_ALLOC_MEM | Cannot grow client table | Check memory |
| -3 | ERR_UNKNOWN_CLIENT | Token doesn't match any client | Client disconnected |

### Firewall Return Codes
| Code | Meaning | Fix |
|------|---------|-----|
| 0 | Success | — |
| -1 | syscfg initialization failed | Check syscfg shared memory |
| -2 | sysevent connection failed | Check syseventd running |
| -3 | Time retrieval error | System clock issue |
| -4 | Mutex file creation failed | /tmp filesystem issue |

## Known Failure Patterns

### Pattern 1: Cascading Failure from Syseventd Restart
```
Signature:
  - Multiple services report "connection refused" in logs
  - All service-status values go stale (no updates)
  - Processes still running but non-responsive

Root Cause: syseventd crashed or was restarted; all client connections invalidated

Recovery:
  1. All services must re-register (restart each or reboot)
  2. Fix: syseventd OOM protection (writes -17 to oom_adj)
```

### Pattern 2: Firewall Mutex Deadlock After OOM Kill
```
Signature:
  - firewall-status stuck at "starting" for >60 seconds
  - /rdklogs/logs/FirewallDebug.txt shows "acquiring mutex..."
  - No "mutex acquired" message follows

Root Cause: Previous firewall process OOM-killed while holding mutex.
            EOWNERDEAD not always delivered if process killed by kernel.

Recovery:
  rm /tmp/firewall_mutex
  killall -9 firewall
  sysevent set firewall-restart
```

### Pattern 3: DHCP Fails Due to Bridge Not Ready
```
Signature:
  - dhcp_server-status = "error" 
  - dnsmasq log: "failed to bind DHCP server socket: No such device"
  - brctl show: bridge not listed

Root Cause: service_dhcp started before multinet created the bridge.
            Race condition in service startup ordering.

Recovery:
  sysevent set multinet_1-up
  # Wait for: sysevent get multinet_1-status = "ready"
  sysevent set dhcp_server-restart
```

### Pattern 4: WAN DHCP Fails — SIGCHLD Inherited
```
Signature:
  - service_wan logs: "system() returned -1"
  - WAN interface up but no DHCP client started

Root Cause: service_wan invoked by syseventd inherits SIG_IGN for SIGCHLD.
            system() then returns -1 because wait() fails.

Fix in code:
  signal(SIGCHLD, SIG_DFL);  // Reset before system() calls
  
Recovery (runtime):
  Manually start: udhcpc -i erouter0 -p /tmp/udhcpc.erouter0.pid -s /usr/bin/service_udhcpc
```

### Pattern 5: Syscfg Corruption on Power Loss
```
Signature:
  - After unexpected reboot, syscfg returns wrong values
  - Log: "syscfg: WARNING - loading from backup file"
  - Or: "syscfg: ERROR - both primary and backup corrupt, loading defaults"

Root Cause: Power lost during syscfg_commit (file write interrupted)

Prevention: Atomic write pattern (write temp → rename). Already implemented.
            Issue occurs if temp file AND rename both interrupted.

Recovery:
  If backup loaded: minimal data loss (last committed state)
  If defaults loaded: factory reset occurred — customer config lost
```

### Pattern 6: Sysevent Worker Threads All Blocked
```
Signature:
  - Events stop being processed
  - sysevent_tracer.txt shows SET entries but no ACTION entries
  - Sanity thread log: "killing blocked process <pid>" after 300s
  
Root Cause: External handler script hangs (infinite loop, blocking I/O),
            consuming all worker threads.

Recovery:
  1. Identify hung processes: ps aux | grep defunct
  2. Kill hung handlers
  3. Workers auto-recover after sanity thread kills blocked processes
  
Prevention: Add timeout to all handler scripts
```

## Dependency Graph (Startup Order)

```
Level 0: Linux kernel + filesystems
    │
Level 1: syscfg_create (shared memory database)
    │
Level 2: syseventd (event bus daemon)
    │
Level 3: apply_system_defaults + service registration
    │
Level 4: ┌─────────────┬───────────────┬──────────────┐
          │ multinet-up │ macclone      │ pmon start   │
          │ (bridges)   │ (WAN MAC)     │ (monitoring) │
          └──────┬──────┴───────────────┴──────────────┘
                 │
Level 5: ┌──────┴──────┬───────────────┐
          │ dhcp-start  │ wan-start     │
          │ (LAN DHCP)  │ (WAN conn)   │
          └─────────────┴───────┬───────┘
                                │
Level 6: ┌──────────────────────┴───────────────────────┐
          │ firewall-restart (needs WAN IP + LAN config) │
          └──────────────────────┬──────────────────────┘
                                 │
Level 7: ┌──────────┬───────────┴──────┬──────────────┐
          │ routing  │ ipv6 services    │ ddns update  │
          └──────────┴──────────────────┴──────────────┘
```

## Configuration Key Categories

| Category | Key Pattern | Example | Service Consumer |
|----------|-------------|---------|-----------------|
| WAN | `wan_*` | `wan_proto=dhcp` | service_wan |
| LAN | `lan_*` | `lan_ipaddr=192.168.1.1` | service_dhcp, firewall |
| DHCP | `dhcp_*` | `dhcp_start=192.168.1.100` | service_dhcp |
| Firewall | `firewall_*`, `*Forward*` | `firewall_level=high` | firewall |
| WiFi | `wl*` | `wl0_ssid=MyNetwork` | utapi_wlan |
| IPv6 | `*v6*`, `router_adv_*` | `dhcpv6s_enable=1` | service_ipv6 |
| System | `device_*`, `hostname` | `hostname=RDK-Gateway` | utapi |
| DDNS | `ddns_*` | `ddns_enable=1` | service_ddns |
| Routing | `rip_*`, `StaticRoute*` | `StaticRoute_1=...` | service_routed |
| MultiNet | (PSM-based) | `dmsb.l2net.1.Name=brlan0` | service_multinet |

## Symptom → Root Cause Quick Reference

| Symptom | Most Likely Root Cause | Verification Command | Fix |
|---------|----------------------|---------------------|-----|
| No internet, WAN IP empty | udhcpc not running or ISP DHCP down | `ps \| grep udhcpc; cat /sys/class/net/erouter0/carrier` | `sysevent set wan-restart` |
| No internet, WAN IP present | Firewall blocking or route missing | `ip route show; iptables -L FORWARD -n \| grep REJECT` | `sysevent set firewall-restart` |
| LAN clients can't get IP | dnsmasq crashed or bridge missing | `ps \| grep dnsmasq; brctl show` | `sysevent set dhcp_server-restart` |
| Config lost after reboot | /nvram full, commit failed | `df /nvram; ls -la /nvram/syscfg.db` | Clear nvram space, `syscfg commit` |
| Service stuck "starting" | Previous handler killed mid-transition | `sysevent get <svc>-status` | Reset status to "stopped", then restart |
| All events stop working | syseventd workers all blocked | `grep BLOCKED sysevent_tracer.txt` | Kill hung handlers, wait 300s for sanity thread |
| Firewall hangs on restart | Mutex deadlock (holder crashed) | `fuser /tmp/firewall_mutex` | `rm /tmp/firewall_mutex; killall firewall` |
| Port forward not working | Rule generated but conntrack stale | `iptables -t nat -L \| grep <port>; conntrack -L` | `conntrack -F; sysevent set firewall-restart` |
| IPv6 not working on LAN | No prefix delegation received | `sysevent get tr_erouter0_dhcpv6_client_v6pref` | Restart WAN (re-triggers DHCPv6) |
| Bridge interface missing | multinet-up not triggered or failed | `brctl show; sysevent get multinet_N-status` | `sysevent set multinet_N-up` |
| DNS not resolving | resolv.conf empty or dnsmasq proxy down | `cat /etc/resolv.conf; ps \| grep dnsmasq` | `sysevent set dhcp_server-restart` |
| DDNS not updating | curl failed or credentials wrong | Check service_ddns log; `syscfg get ddns_enable` | `sysevent set ddns-retry` |
| Routing broken after WAN up | zebra/ripd not started | `ps \| grep zebra` | `sysevent set service_routed-restart` |
| Device stuck in wrong mode | DeviceMode switch incomplete | Check service_devicemode log | Manually call `service_devicemode DeviceMode <0\|1>` |
