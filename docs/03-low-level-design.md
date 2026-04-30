# Low-Level Design (LLD)

## 1. Syscfg Module

### Data Structures

```c
// Shared memory control block
struct syscfg_shm_ctx {
    shm_cb *cb;            // Control block in shared memory
    int     shm_fd;        // Shared memory file descriptor
    size_t  shm_size;      // Total shared memory size
};

// Hash table entry (stored in shared memory at offsets)
struct ht_entry {
    int   name_sz;         // Key length
    int   value_sz;        // Value length
    int   next;            // Offset to next entry (0 = end)
    // followed by: name[name_sz] + value[value_sz]
};

// Default value node (in-process linked list)
struct ConfigNode {
    char *key;
    char *value;
    struct ConfigNode *next;
};
```

### Hash Table Implementation
- **Algorithm:** djb2 (`hash = hash * 33 + c`)
- **Bucket count:** `SYSCFG_HASH_TABLE_SZ` (compile-time constant)
- **Collision resolution:** Separate chaining via offset-based linked lists in shared memory
- **Storage:** All data stored as offsets from shared memory base (portable across processes)

### Locking Strategy

```
┌─────────────────────────────────────────┐
│  Three-Lock Protocol                     │
│                                          │
│  read_lock   - Multiple readers allowed  │
│  write_lock  - Exclusive writer access   │
│  commit_lock - Exclusive file I/O        │
│                                          │
│  EOWNERDEAD handling:                    │
│    pthread_mutex_consistent() → recover  │
│    Continue operation (no data loss)     │
└─────────────────────────────────────────┘
```

### State Machine

```
              syscfg_create()
                    │
                    ▼
┌──────────────────────────────────┐
│         UNINITIALIZED            │
└──────────────────────────────────┘
                    │ shmget/shmat + load_from_file
                    ▼
┌──────────────────────────────────┐
│            ACTIVE                │◄──────────────────┐
│  (shared memory ready)           │                   │
└──────────────────────────────────┘                   │
        │                   │                          │
  syscfg_set()        syscfg_commit()                  │
        │                   │                          │
        ▼                   ▼                          │
┌──────────────┐  ┌──────────────────┐                │
│   MODIFIED   │  │   COMMITTING     │                │
│(in-memory)   │  │(write to file)   │────────────────┘
└──────────────┘  └──────────────────┘
        │
  syscfg_commit()
        │
        ▼
  (write to file → back to ACTIVE)
```

---

## 2. Sysevent Module

### Client Manager Data Structures

```c
typedef unsigned int token_t;

typedef struct {
    int     used;            // Slot active flag
    token_t id;              // Unique client token
    int     fd;              // Socket file descriptor
    int     notifications;   // Notification count
    int     errors;          // Error count
    char    name[15];        // Client identifier
    int     isData;          // Data-only client flag
} a_client_t;

typedef struct {
    pthread_mutex_t mutex;
    int   num_cur_clients;
    int   max_cur_clients;   // Grows dynamically
    a_client_t *clients;     // Dynamic array
} clients_t;
```

### Trigger Manager Data Structures

```c
typedef struct {
    int     used;
    token_t owner;           // Owning client token
    int     action_flags;
    int     action_type;     // ACTION_TYPE_EXT_FUNCTION | ACTION_TYPE_MESSAGE
    int     action_id;
    char   *action;          // Executable path or message format
    int     argc;
    char  **argv;            // Additional arguments
} trigger_action_t;

typedef struct {
    int     used;
    int     trigger_id;
    int     max_actions;
    int     num_actions;
    int     next_action_id;
    trigger_action_t *trigger_actions;
    int     trigger_flags;   // TUPLE_FLAG_SERIAL, TUPLE_FLAG_EVENT, etc.
} trigger_t;
```

### Event Processing Sequence

```
Client: sysevent_set("wan-status", "started")
    │
    ▼
Worker Thread receives SE_MSG_SET message
    │
    ▼
DATA_MGR_set("wan-status", "started")
    │
    ├── Compare with current value
    │   └── If unchanged → return (no trigger)
    │
    ├── Update data_element_t.value
    │
    └── If trigger_id != 0:
            │
            ▼
        Write trigger_id to trigger_communication_pipe
            │
            ▼
        Worker reads from pipe → TRIGGER_MGR.execute_trigger_actions()
            │
            ├── For each ACTION_TYPE_MESSAGE:
            │       Build SE_MSG_SEND_NOTIFICATION
            │       Send to client FD (CLI_MGR_id2fd)
            │
            └── For each ACTION_TYPE_EXT_FUNCTION:
                    Build SE_MSG_RUN_EXTERNAL_EXECUTABLE
                    Send to fork_helper via pipe
                    Fork helper: fork() + execve(action_path)
```

### Worker Thread State Machine

```
┌─────────────┐   semaphore wait   ┌─────────────┐
│    IDLE      │──────────────────►│   ACTIVE     │
└─────────────┘                    └─────────────┘
       ▲                                  │
       │                                  ▼
       │                           Process message:
       │                           - SE_MSG_SET
       │                           - SE_MSG_GET  
       │                           - SE_MSG_SET_OPTIONS
       │                           - SE_MSG_REMOVE_ASYNC
       │                           - SE_MSG_CLOSE
       │                                  │
       └──────────────────────────────────┘
                 message processed
```

### Sanity Thread Logic

```
Every 5 seconds:
    For each entry in blocked_exec_list:
        increment mark_counter
        If mark_counter > MAX_ACTIVATION_BLOCKING_SECS/5:
            kill(pid, SIGKILL)
            remove from list
            log "killed blocked process"
```

---

## 3. Firewall Module

### Rule Generation Pipeline

```
service_start()
    │
    ├── fw_shm_mutex_init() → acquire process mutex
    │
    ├── Initialize: sysevent_open + syscfg_init
    │
    ├── Read ALL configuration:
    │   - WAN IP/interface/protocol
    │   - LAN settings (IP, mask, bridge)
    │   - Port forwarding rules
    │   - DMZ configuration
    │   - ACL/MAC filtering
    │   - QoS rules
    │   - Parental controls
    │
    ├── prepare_ipv4_firewall("/tmp/.ipt")
    │   ├── raw table rules
    │   ├── mangle table (QoS marks, DSCP)
    │   ├── nat table (DNAT, SNAT, masquerade)
    │   └── filter table (all chains)
    │
    ├── prepare_ipv6_firewall("/tmp/.ipt_v6")
    │   └── (similar structure for IPv6)
    │
    ├── system("iptables-restore < /tmp/.ipt")
    │   system("ip6tables-restore < /tmp/.ipt_v6")
    │
    └── sysevent_set("firewall-status", "started")
```

### Iptables Chain Architecture

```
                        PREROUTING
                            │
              ┌─────────────┼─────────────┐
              │             │             │
         prerouting_    prerouting_   prerouting_
         fromwan        fromlan       trigger
              │             │
              ▼             ▼
            INPUT        FORWARD
              │             │
        ┌─────┴─────┐  ┌───┴───────────┐
        │           │  │               │
    wan2self    lan2self  lan2wan    wan2lan
                           │
                    ┌──────┴──────┐
                    │            │
               wan2lan_     wan2lan_
               accept      dns_intercept
                            
                        POSTROUTING
                            │
                    postrouting_towan
```

### Mutex Design (Cross-Process)

```c
// Shared memory mutex for process-level firewall serialization
#define SHM_MUTEX "/tmp/firewall_mutex"

fw_shm_mutex_init():
    fd = open(SHM_MUTEX, O_CREAT|O_RDWR)
    ftruncate(fd, sizeof(pthread_mutex_t))
    mmap → pshared_mutex
    pthread_mutexattr_setpshared(PTHREAD_PROCESS_SHARED)
    pthread_mutexattr_setrobust(PTHREAD_MUTEX_ROBUST)
    pthread_mutex_init(pshared_mutex)

// On EOWNERDEAD:
    pthread_mutex_consistent(pshared_mutex)  // Mark consistent
    // Continue execution (previous holder crashed)
```

---

## 4. Service DHCP Module

### Event Handler Dispatch

```c
static const struct cmd_entry cmd_table[] = {
    {"dhcp_server-restart",  dhcp_server_restart},
    {"dhcp_server-start",    dhcp_server_start},
    {"dhcp_server-stop",     dhcp_server_stop},
    {"lan-status",           lan_status_change},
    {"bring-lan",            bring_lan_up},
    {"ipv4_N-status",        ipv4_status},
    {"ipv4-up",              ipv4_up},
    {"ipv4-down",            teardown_instance},
    {"multinet_N-status",    handle_l2_status},
    ...
};
```

### DHCP Server Lifecycle

```
dhcp_server_start()
    │
    ├── wait_till_end_state("dhcp_server", 9 retries, 1s each)
    │   └── Ensures no concurrent start/stop transition
    │
    ├── sysevent_set("dhcp_server-status", "starting")
    │
    ├── Read pool configuration from syscfg:
    │   - Pool ranges
    │   - Static leases
    │   - Options (DNS, gateway, lease time)
    │
    ├── Generate /etc/dnsmasq.conf
    │
    ├── Start dnsmasq process
    │
    └── sysevent_set("dhcp_server-status", "started")

dhcp_server_stop()
    │
    ├── sysevent_set("dhcp_server-status", "stopping")
    ├── kill dnsmasq (SIGTERM via PID file)
    └── sysevent_set("dhcp_server-status", "stopped")
```

---

## 5. Service WAN Module

### State Structure

```c
struct serv_wan {
    int             sefd;              // sysevent FD
    int             setok;             // sysevent token
    char            ifname[IFNAMSIZ];  // WAN interface (e.g., erouter0)
    enum wan_rt_mod rtmod;             // IPv4Only/IPv6Only/DualStack/Unknown
    enum wan_prot   prot;              // DHCP/Static
    int             timo;              // DHCP timeout
};
```

### WAN Connection State Machine

```
           wan_start()
               │
               ▼
┌────────────────────────┐
│     INITIALIZING       │
│  - Read wan_proto      │
│  - Read erouter_mode   │
│  - Set interface name  │
└────────────────────────┘
               │
               ▼
┌────────────────────────┐         wan_iface_down()
│    INTERFACE_UP        │◄────────────────────┐
│  - ifconfig up         │                     │
│  - sysctl forwarding   │                     │
└────────────────────────┘                     │
               │                               │
               ▼                               │
┌────────────────────────┐                     │
│   DHCP_REQUESTING      │  lease fail         │
│  - Start udhcpc        │────────────────────►│
│  - Wait for lease      │                     │
└────────────────────────┘                     │
               │ lease acquired                │
               ▼                               │
┌────────────────────────┐                     │
│      CONNECTED         │                     │
│  - Set routes          │                     │
│  - Set DNS             │  link down          │
│  - Fire wan-started    │─────────────────────┘
└────────────────────────┘
```

---

## 6. Trigger Module (Port Triggering)

### NFQ Processing Loop

```c
main_loop():
    while(1):
        select(nfq_fd, timeout=trigger_lifetime)
        
        if (fd readable):
            nfq_handle_packet()  // → trigger_callback()
        
        if (timeout):
            update_quanta()      // Decrement all active triggers
            expire_triggers()    // Remove expired, cleanup rules
```

### Trigger Activation Flow

```
Packet on NFQ 22 → trigger_callback(mark, src_addr)
    │
    ├── Extract trigger index from mark
    │
    ├── update_trigger_entry(mark, saddr):
    │   ├── Read syscfg "PortRangeTrigger_<mark>"
    │   ├── Parse: enabled,protocol,trigger_range,forward_range,lifetime
    │   └── Populate trigger_info[mark]
    │
    ├── start_forwarding(id):
    │   ├── Build DNAT rule string
    │   ├── sysevent_set_unique("NatFirewallRule", rule)
    │   ├── Build FORWARD ACCEPT rule
    │   ├── sysevent_set_unique("GeneralPurposeFirewallRule", rule)
    │   └── sysevent_set("firewall-restart")
    │
    └── Set trigger_info[id].active = 1
                                        
Expiry: quanta reaches 0 → stop_forwarding(id)
    ├── sysevent_del_unique(rule_handles)
    └── sysevent_set("firewall-restart")
```

---

## 7. UTCTX Transaction Layer

### Transaction Commit Sequence

```c
Utopia_Free(ctx):
    │
    ├── For each node in transaction list:
    │   ├── Determine target: syscfg or sysevent
    │   ├── syscfg_set(namespace, key, value)
    │   └── Accumulate event flags (bitmask)
    │
    ├── syscfg_commit()  // Atomic persist
    │
    ├── s_UtopiaEvent_Trigger(accumulated_flags):
    │   │  For each bit set in event_flags:
    │   │      sysevent_set(g_Utopia_Events[bit].event_key, value)
    │   │
    │   │  If any event has wait_key:
    │   │      s_UtopiaEvent_Wait(wait_key, wait_value, timeout)
    │   │      // Blocking wait for service completion
    │   │
    │   └── Return
    │
    └── sysevent_close(ctx->fd, ctx->token)
```

### Value Type Resolution

```c
Utopia_Get(ctx, UtopiaValue_WanProto, buf, sz):
    │
    ├── Lookup g_Utopia[UtopiaValue_WanProto]:
    │   type = Utopia_Type_Config
    │   key  = "wan_proto"
    │   ns   = NULL (global namespace)
    │
    ├── UtopiaTransact_Get():
    │   ├── Check transaction buffer (pending writes)
    │   └── If not found: syscfg_get(ns, key, buf, sz)
    │
    └── Return value
```

---

## 8. Service Registration (srvmgr)

### Registration Protocol

```c
sm_register(service_name, se_fd, se_token):
    │
    ├── Register default events:
    │   sysevent_setcallback(fd, token,
    │       "<service>-start",
    │       SE_FLAG_NORMAL,
    │       "/path/to/handler start",
    │       TUPLE_FLAG_EVENT)
    │
    │   sysevent_setcallback(... "<service>-stop" ...)
    │   sysevent_setcallback(... "<service>-restart" ...)
    │
    ├── Register custom events:
    │   For each custom_event in definitions:
    │       parse event spec: "event|handler|flags|tuple_flags|params"
    │       sysevent_setcallback(...)
    │
    └── Store async_ids via sysevent_set:
        "xsm_<service>_async_id_<event>" = "<event> 0x<trigger_id> 0x<action_id>"
```

### Service State Protocol

Every service follows this state convention:

```
sysevent "<service>-status" values:
    "stopped"   → Service not running
    "starting"  → Service initialization in progress
    "started"   → Service running and healthy
    "stopping"  → Service shutdown in progress
    "error"     → Service in error state
```

Services check state before start/stop to prevent races:
```c
wait_till_end_state(service):
    for i in 0..9:
        status = sysevent_get("<service>-status")
        if status == "starting" || status == "stopping":
            sleep(1)
            continue
        else:
            return  // Safe to proceed
```
