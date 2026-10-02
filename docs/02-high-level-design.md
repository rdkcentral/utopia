# High-Level Design (HLD)

## System Architecture

Utopia operates as a layered service-oriented system providing infrastructure and networking services to the RDK-B middleware stack.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    RDK-B Management Layer                            │
│         (TR-069, WebPA, USP, WebUI, CcspPandM, CcspPsm)           │
├─────────────────────────────────────────────────────────────────────┤
│                    UTAPI / UTCTX (API Layer)                         │
│         Typed config getters/setters, transaction context           │
├────────────────────────┬────────────────────────────────────────────┤
│   Syscfg (Config DB)   │        Sysevent (Event Bus)                │
│   Shared memory +      │   Unix domain socket server +              │
│   filesystem backing   │   trigger-based action dispatch            │
├────────────────────────┴────────────────────────────────────────────┤
│                    Network Services Layer                            │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐          │
│  │ Firewall │   DHCP   │   WAN    │  Routing │   IPv6   │          │
│  ├──────────┼──────────┼──────────┼──────────┼──────────┤          │
│  │ MultiNet │  Trigger │  DDN S   │ DSLite   │ DevMode  │          │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘          │
├─────────────────────────────────────────────────────────────────────┤
│                    Support Services                                   │
│         (pmon, newhost, macclone, ulog, walled_garden)              │
├─────────────────────────────────────────────────────────────────────┤
│                    Platform Layer                                     │
│  Linux Kernel │ HAL APIs │ iptables │ ip route │ External Daemons   │
└─────────────────────────────────────────────────────────────────────┘
```

## Major Components

### 1. Syscfg — Configuration Persistence Engine

**Architecture:** Process-shared POSIX shared memory segment containing a hash table (djb2 hash, configurable bucket count). Filesystem-backed for persistence across reboots.

**Design Decisions:**
- Shared memory for sub-millisecond cross-process reads (no IPC round-trip)
- Robust POSIX mutexes handle process crashes (EOWNERDEAD recovery)
- Dual-file backing (primary + backup) for corruption resilience
- Namespace support for multi-tenant isolation

**Data Flow:**
```
syscfg_set() → acquire write_lock → update hash table in shm → release lock
syscfg_commit() → acquire commit_lock → serialize hash table → write to file → release lock
syscfg_get() → acquire read_lock → lookup hash table → copy value → release lock
```

### 2. Sysevent — Event Bus Daemon

**Architecture:** Multi-threaded daemon (1 main + N workers + 1 sanity) serving TCP and Unix domain socket clients. Implements pub-sub with trigger-based action dispatch.

**Design Decisions:**
- select()-based I/O multiplexing on main thread for connection acceptance
- Worker thread pool (default 10) for event processing parallelism
- Fork helper child process for external executable invocation
- Serial execution mode for ordered action sequences
- Named FIFOs for fork-helper→worker result delivery

**Component Structure:**
```
syseventd
├── Main Thread (accept loop, client token assignment)
├── Worker Threads[N] (event processing, action dispatch)  
├── Sanity Thread (watchdog: kill blocked processes >300s)
├── Fork Helper (child process for external exec)
├── ClientsMgr (dynamic client table, FD↔token mapping)
├── TriggerMgr (action registry, serial/parallel dispatch)
└── DataMgr (tuple storage, change detection, trigger firing)
```

### 3. UTAPI/UTCTX — API and Context Layer

**Architecture:** Two-tier abstraction:
- **UTCTX** (lower): Transaction manager buffering reads/writes, committing atomically
- **UTAPI** (upper): Typed domain-specific APIs (LAN, WAN, DHCP, Firewall, WLAN)

**Design Pattern:** Unit-of-Work
```
Utopia_Init() → open sysevent connection
  Utopia_Set() × N → buffer changes in linked list
Utopia_Free() → commit to syscfg → fire accumulated events → close
```

### 4. Network Services

All network services follow a common architectural pattern:

```
┌─────────────────────────────────────────┐
│            Service Binary                 │
├─────────────────────────────────────────┤
│  main() → parse CLI args → dispatch     │
│  ┌───────────────────────────────────┐  │
│  │  State Structure (serv_xxx)       │  │
│  │  - sysevent fd/token              │  │
│  │  - service-specific state         │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │  Command Dispatch Table           │  │
│  │  cmd_ops[] = {name, handler_fn}   │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │  Handlers                         │  │
│  │  - start/stop/restart             │  │
│  │  - event-specific logic           │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│  IPC: sysevent_open/get/set/close       │
│  Config: syscfg_get/set/commit          │
│  Platform: v_secure_system / HAL APIs   │
└─────────────────────────────────────────┘
```

### 5. Service Manager (srvmgr)

**Role:** Registers services with sysevent for event-driven activation.

**Registration Pattern:**
```
sm_register(service_name, default_events[], custom_events[])
  → sysevent_setcallback(event, handler_path, flags)
  → store async_id for later cancellation
```

## Component Interactions

### Event-Driven Orchestration

```
Configuration Change (e.g., DHCP pool update)
    │
    ▼
UTAPI → syscfg_set() → syscfg_commit()
    │
    ▼
UTCTX posts "dhcp_server-restart" to sysevent
    │
    ▼
Sysevent TriggerMgr matches registered callback
    │
    ▼
Fork Helper executes: /usr/bin/service_dhcp dhcp_server-restart
    │
    ▼
service_dhcp: stops dnsmasq → regenerates config → starts dnsmasq
    │
    ▼
service_dhcp posts "dhcp_server-status" = "started" to sysevent
```

### Cross-Service Dependencies

```
                    firewall-restart
                         ▲
                         │
    ┌────────────────────┼────────────────────┐
    │                    │                    │
wan-status          lan-status         newhost-trigger
    │                    │                    │
service_wan        service_dhcp           newhost
    │                    │
    ▼                    ▼
 routing            dhcp_server
```

## External Dependencies

### Runtime Dependencies

| Dependency | Type | Used By | Failure Impact |
|---|---|---|---|
| dnsmasq | External daemon | service_dhcp | No DHCP/DNS on LAN |
| udhcpc / ti_udhcpc | External daemon | service_wan | No WAN IP acquisition |
| dibbler-server | External daemon | service_ipv6 | No DHCPv6 on LAN |
| zebra / ripd | External daemon | service_routed | No dynamic routing |
| radvd | External daemon | service_routed | No IPv6 RA on LAN |
| iptables / ip6tables | System utility | firewall | No packet filtering |
| ip (iproute2) | System utility | Multiple | No routing/interface config |
| curl | System utility | service_ddns | No DDNS updates |
| conntrack_delete | System utility | walled_garden | Stale connections persist |
| cron | System service | Multiple | No scheduled operations |

### Library Dependencies

| Library | Purpose | Linked By |
|---|---|---|
| libsyscfg | Configuration API | All services |
| libsysevent | Event bus client API | All services |
| libulog | Logging | All services |
| libccsp_common | CCSP IPC framework | firewall, service_dhcp, service_routed |
| libsafec | Safe C string operations | All services |
| libnetfilter_queue | NFQ packet handling | trigger |
| libdbus-1 | D-Bus IPC | firewall, service_dhcp |
| libcjson | JSON parsing | apply_system_defaults |
| libnet | Network operations | macclone (optional) |

### Filesystem Dependencies

| Path | Purpose | Critical |
|---|---|---|
| `/nvram/syscfg.db` | Primary persistent config | Yes |
| `/opt/secure/data/syscfg.db` | Alternate config location | Platform-specific |
| `/etc/utopia/system_defaults` | Factory default values | Yes (first boot) |
| `/etc/utopia/service.d/` | Service handler scripts | Yes |
| `/tmp/syseventd_connection` | Sysevent UDS path | Yes (runtime) |
| `/var/run/syseventd.pid` | Daemon PID file | Yes (singleton) |
| `/tmp/.ipt` / `/tmp/.ipt_v6` | Firewall rule staging | Yes (firewall) |
| `/rdklogs/logs/` | Runtime log directory | No (degraded logging) |

## Threading Model

| Component | Model | Details |
|---|---|---|
| syseventd | Multi-threaded | 1 main + 10 workers + 1 sanity + 1 fork helper |
| syscfg | Lock-based shared | POSIX robust mutexes across processes |
| Network services | Single-threaded | Each runs as separate process |
| Firewall | Single-threaded | Process-level mutex for serialization |
| Trigger | Single-threaded | select() event loop with NFQ |

## Scalability Design

- **Horizontal:** New services register with sysevent independently
- **Vertical:** Worker thread pool in syseventd scales event processing
- **Modularity:** Conditional compilation enables/disables features per platform
- **Isolation:** Each service runs as separate process (fault isolation)
