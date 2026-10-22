# External Dependencies & Integration

## Dependency Matrix

| Dependency | Category | Used By | Communication | Failure Impact | Recovery |
|---|---|---|---|---|---|
| dnsmasq | Daemon | service_dhcp | Process management (PID file) | No DHCP/DNS on LAN | pmon auto-restart |
| udhcpc | Daemon | service_wan | Script callback | No WAN IP | WAN service retry |
| dibbler-server | Daemon | service_ipv6 | Process management | No DHCPv6 | Service restart |
| zebra/ripd | Daemon | service_routed | Config file + signals | No dynamic routing | Service restart |
| radvd | Daemon | service_routed | Config file + HUP | No IPv6 RA | Service restart |
| iptables | Kernel utility | firewall | iptables-restore pipe | No packet filtering | Firewall restart |
| iproute2 (ip) | Utility | Multiple | Command execution | No routing config | Manual intervention |
| curl | Utility | service_ddns | HTTP client | DDNS update fails | Cron retry with backoff |
| conntrack tools | Utility | firewall, walled_garden | Command execution | Stale connections | Non-critical |
| cron (crond) | Daemon | Multiple | Cron job registration | No scheduled tasks | crond-restart event |
| D-Bus | IPC framework | firewall, service_dhcp | libdbus API | No CCSP access | Component restart |
| RBus | IPC framework | UTAPI | Message API | Degraded management | Fallback to direct |

## Detailed Integration Points

### 1. dnsmasq (DHCP Server + DNS Proxy)

**Interaction Pattern:**
```
service_dhcp → generates /etc/dnsmasq.conf → starts dnsmasq process
service_dhcp → monitors via PID file (/var/run/dnsmasq.pid)
dnsmasq → serves DHCP to LAN clients
dnsmasq → provides DNS proxy/cache
```

**Configuration Generation:**
- Pool ranges from syscfg (`dhcp_start`, `dhcp_end`)
- Static leases from syscfg (`dhcp_static_host_N`)
- DNS upstream from sysevent (`wan_dns`)
- Interface binding from multinet config

**Failure Scenarios:**
| Symptom | Root Cause | Detection |
|---|---|---|
| LAN clients get no IP | dnsmasq crashed | pmon check, missing PID |
| DNS timeout on LAN | dnsmasq not responding | Health check failure |
| Wrong DHCP pool | Config regeneration failed | DHCP lease logs |

### 2. udhcpc (WAN DHCP Client)

**Interaction Pattern:**
```
service_wan → starts udhcpc with -s /usr/bin/service_udhcpc
udhcpc → DHCP discovery on WAN interface
udhcpc → calls service_udhcpc with bound/renew/deconfig
service_udhcpc → updates sysevent (wan_ipaddr, wan_dns, wan_status)
```

**Critical Events:**
- `bound`: First IP acquired → full WAN initialization
- `renew`: Lease renewed → check for IP change
- `deconfig`: Lease lost → WAN down, clear all state
- `leasefail`: DHCP failed → retry or WAN Manager notification

**Failure Impact:**
- udhcpc crash → No WAN IP renewal → eventual lease expiry → connectivity loss
- Slow DHCP server → WAN comes up late → dependent services delayed

### 3. Linux Netfilter (iptables/ip6tables)

**Interaction Pattern:**
```
firewall module → generates rule file → iptables-restore (atomic apply)
trigger module → individual rule insertion via sysevent pools
walled_garden scripts → individual iptables commands
```

**Critical Notes:**
- Atomic restore prevents partial rule state
- Rule count can reach thousands (enterprise deployments)
- conntrack flush after rule change prevents stale connections
- NFQ (netfilter queue) used by trigger module for packet inspection

**Failure Scenarios:**
| Symptom | Root Cause | Detection |
|---|---|---|
| All traffic blocked | iptables-restore syntax error | Firewall status != "started" |
| Partial filtering | Race during apply | Mutex contention log |
| NFQ not working | Module not loaded | trigger daemon log |

### 4. CCSP/D-Bus Integration

**Used By:** firewall (PSM queries), service_dhcp (bus init), service_routed (PSM queries)

**Pattern:**
```c
// Initialize
CCSP_Message_Bus_Init(component_id, config_file, &bus_handle)

// Query PSM
PSM_Get_Record_Value2(bus_handle, CCSP_SUBSYS, key, &type, &value)

// Query TR-181 Data Model
CcspBaseIf_getParameterValues(bus_handle, component, dbus_path,
                               param_names, param_count, &size, &val)
```

**Failure Impact:**
- D-Bus unavailable → Cannot read PSM values → Use defaults/cached
- Component not registered → Query times out → Service degradation

### 5. HAL Layer Integration

**Network HAL:**
```
wifi_hal_init() → WiFi hardware initialization
wifi_hal_getSSIDName() → SSID configuration
ethernet_hal_getEthWanLinkStatus() → Physical link monitoring
docsis_hal_GetDhcpInfo() → Cable modem DHCP info
platform_hal_GetDeviceConfigStatus() → System health
```

**Failure Impact:**
- HAL init failure → Hardware not controllable → Feature disabled
- HAL stale data → Incorrect state in sysevent → Cascading misconfig

### 6. Persistent Storage

**Primary:** `/nvram/syscfg.db` — main configuration database
**Backup:** `/nvram/syscfg.db.prev` or `/opt/secure/data/syscfg.db`

**Corruption Recovery:**
```
syscfg_create():
    Try primary file → if corrupt:
        Try backup file → if corrupt:
            Load /etc/utopia/system_defaults (factory reset)
```

**Write Pattern:**
- syscfg_commit() serializes entire hash table to temp file
- Rename (atomic) onto target path
- Backup file updated on successful commit

## Dependency Startup Order

```
1. Linux kernel + filesystem mounted
2. syscfg_create (shared memory + file load)
3. syseventd (event bus ready)
4. apply_system_defaults (config baseline)
5. Service registration (callbacks installed)
6. LAN services (multinet → DHCP → firewall)
7. WAN services (interface up → DHCP client)
8. Post-WAN services (routing, IPv6, DDNS)
9. CCSP components (depend on syscfg + sysevent)
```

## Dependency Failure Matrix

| Failed Dependency | Immediate Impact | Cascading Impact | Auto-Recovery | Manual Fix |
|---|---|---|---|---|
| syscfg shm | All config reads fail | All services fail | Reboot | Check shm limits |
| syseventd crash | No IPC delivery | All services orphaned | Reboot required | Fix OOM/bug |
| dnsmasq crash | No new DHCP leases | Clients lose connectivity | pmon restart | Check config |
| udhcpc crash | No WAN lease renewal | WAN IP lost eventually | WAN service retry | Restart service_wan |
| iptables module | Firewall rules fail | No packet filtering | Module reload | Kernel config |
| D-Bus daemon | No PSM/CCSP access | Management plane down | systemd restart | Check bus config |
| /nvram full | syscfg_commit fails | Config changes lost | None (auto) | Clear nvram space |
| dibbler crash | No DHCPv6 service | IPv6 degraded | Service restart | Check config |
| zebra/ripd | No dynamic routing | Static routes only | pmon/service restart | Check routing config |
