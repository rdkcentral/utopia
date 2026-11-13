# Architecture Deep Dive — Core Subsystems

## Syscfg Internal Architecture

### Memory Layout

```
Shared Memory Segment (syscfg)
┌──────────────────────────────────────────────────┐
│  Control Block (shm_cb)                           │
│  ├── read_lock (pthread_mutex_t, ROBUST)         │
│  ├── write_lock (pthread_mutex_t, ROBUST)        │
│  ├── commit_lock (pthread_mutex_t, ROBUST)       │
│  ├── store_path[128] ("/nvram/syscfg.db")        │
│  ├── max_size                                     │
│  ├── used_size                                    │
│  └── entry_count                                  │
├──────────────────────────────────────────────────┤
│  Hash Table Buckets [SYSCFG_HASH_TABLE_SZ]       │
│  bucket[0] → offset to first ht_entry            │
│  bucket[1] → offset to first ht_entry            │
│  ...                                              │
│  bucket[N] → 0 (empty)                           │
├──────────────────────────────────────────────────┤
│  ht_entry pool (variable size)                    │
│  ┌─────────────────────────────────┐             │
│  │ name_sz | value_sz | next_offset│             │
│  │ name_bytes[name_sz]             │             │
│  │ value_bytes[value_sz]           │             │
│  └─────────────────────────────────┘             │
│  ... more entries ...                             │
└──────────────────────────────────────────────────┘
```

### Read/Write Concurrency Model

```
Reader:
  acquire(read_lock)           ← blocks only if writer active
  result = hash_lookup(key)
  release(read_lock)
  return result

Writer:
  acquire(write_lock)          ← exclusive
  hash_insert_or_update(key, value)
  release(write_lock)

Committer:
  acquire(commit_lock)         ← exclusive, independent of read/write
  serialize_hash_table_to_file()
  atomic_rename(tmp_file, store_path)
  release(commit_lock)
```

### Corruption Detection & Recovery

```
_syscfg_find_corrupted_keys():
  For each entry in hash table:
    Validate: name_sz > 0, value_sz >= 0
    Validate: name contains only printable chars
    Validate: next_offset within bounds or 0
    Cross-reference with system_defaults keys (optional)
  Report: corrupted entries found

Recovery path:
  If minor corruption (few bad entries):
    → Remove corrupted entries, reconstruct linkage
  If major corruption (control block damaged):
    → Destroy shared memory
    → Recreate from backup file
    → If backup corrupt: factory reset from system_defaults
```

---

## Sysevent Internal Architecture

### Thread Communication Design

```
                    ┌─────────────────────────────────────┐
                    │           MAIN THREAD                 │
                    │  select() on TCP_fd + UDS_fd         │
                    │  accept() → assign token →           │
                    │  write(main_pipe) → notify workers   │
                    └──────────────┬──────────────────────┘
                                   │ main_communication_pipe
                    ┌──────────────▼──────────────────────┐
                    │         WORKER THREADS [0..N]         │
                    │  sem_wait(worker_sem)                 │
                    │  read from main_pipe OR trigger_pipe  │
                    │  process SE_MSG_*                     │
                    │  ├── SE_MSG_SET → DataMgr.set()       │
                    │  │   └── if changed: write trigger_pipe│
                    │  ├── SE_MSG_GET → DataMgr.get()       │
                    │  ├── SE_MSG_CLOSE → ClientsMgr.remove()│
                    │  └── SE_MSG_SET_OPTIONS → flags update │
                    └──────────────┬──────────────────────┘
                                   │ trigger_communication_pipe
                    ┌──────────────▼──────────────────────┐
                    │       TRIGGER PROCESSING              │
                    │  Read trigger_id from pipe            │
                    │  TriggerMgr.execute_trigger_actions() │
                    │  ├── ACTION_TYPE_MESSAGE:             │
                    │  │   send notification to client FD   │
                    │  └── ACTION_TYPE_EXT_FUNCTION:        │
                    │      write to fork_helper_pipe         │
                    └──────────────┬──────────────────────┘
                                   │ fork_helper_pipe
                    ┌──────────────▼──────────────────────┐
                    │        FORK HELPER PROCESS            │
                    │  (separate child process)             │
                    │  Read action from pipe                │
                    │  fork() → execve(handler_binary, args)│
                    │  Write result to worker FIFO          │
                    │  (/tmp/syseventd_worker_N)            │
                    └──────────────────────────────────────┘
```

### Message Protocol (SE_MSG)

```
Message Header:
┌────────────────────────────────────┐
│ msg_type (uint32)                  │  SE_MSG_SET, SE_MSG_GET, etc.
│ msg_size (uint32)                  │  Total message size
│ token (uint32)                     │  Client authentication
│ async_id (uint32)                  │  For async operations
└────────────────────────────────────┘

Message Types:
  SE_MSG_OPEN_CONNECTION    → Client registration
  SE_MSG_CLOSE_CONNECTION   → Client deregistration
  SE_MSG_SET                → Set tuple value
  SE_MSG_GET                → Get tuple value
  SE_MSG_SET_OPTIONS        → Set tuple flags
  SE_MSG_REMOVE_ASYNC       → Remove async callback
  SE_MSG_SEND_NOTIFICATION  → Trigger notification to client
  SE_MSG_RUN_EXTERNAL_EXECUTABLE → Execute via fork helper
  SE_MSG_EXECUTE_SERIALLY   → Serial execution group
  SE_MSG_DIE                → Shutdown signal to workers
```

### Tuple Flags

```
TUPLE_FLAG_EVENT       (0x00000001) — Value is an event (triggers on any set)
TUPLE_FLAG_SERIAL      (0x00000002) — Actions execute serially (ordered)
TUPLE_FLAG_NORMAL      (0x00000000) — Default: parallel execution, trigger on change
```

---

## Firewall Rule Generation Engine

### Pipeline Stages

```
Stage 1: Configuration Collection
  ├── WAN config (interface, IP, protocol, MTU)
  ├── LAN config (bridges, IPs, subnets)
  ├── Feature flags (DMZ, port_forward_enabled, etc.)
  ├── Rule sets (PortForward_1..N, PortTrigger_1..N)
  ├── Security (firewall_level, block_ping, block_ident)
  ├── QoS (policies, DSCP marks)
  └── Parental (managed sites/services, time windows)

Stage 2: Rule Composition
  ├── For each table (raw, mangle, nat, filter):
  │   ├── Write table header (*raw / *mangle / *nat / *filter)
  │   ├── Declare chains (:CHAIN_NAME POLICY)
  │   ├── Generate rules per function (20+ sub-generators)
  │   └── Write COMMIT
  │
  ├── Sub-generators (partial list):
  │   ├── do_raw_table_general_rules()
  │   ├── do_mangle_qos_marking()
  │   ├── do_nat_port_forwarding()
  │   ├── do_nat_dmz()
  │   ├── do_nat_masquerade()
  │   ├── do_filter_wan2self()
  │   ├── do_filter_lan2wan()
  │   ├── do_filter_wan2lan()
  │   ├── do_filter_rate_limiting()
  │   └── do_filter_logging()
  │
  └── Dynamic rules (from sysevent pools):
      ├── "NatFirewallRule" pool → NAT table rules
      ├── "GeneralPurposeFirewallRule" pool → filter FORWARD rules
      └── "v6GeneralPurposeFirewallRule" pool → ip6tables rules

Stage 3: Atomic Application
  ├── iptables-restore < /tmp/.ipt
  ├── ip6tables-restore < /tmp/.ipt_v6
  └── conntrack -F (flush stale entries)
```

### Dynamic Rule Pool Mechanism

Services (like trigger module) can inject firewall rules at runtime without regenerating the entire ruleset:

```
Injection:
  sysevent_set_unique("NatFirewallRule",
    "-A prerouting_fromwan -p tcp --dport 8080 -j DNAT --to 192.168.1.100:80")
  → Returns handle_id for later removal
  sysevent_set("firewall-restart")

Removal:
  sysevent_del_unique("NatFirewallRule", handle_id)
  sysevent_set("firewall-restart")

During regeneration:
  firewall iterates all pool entries:
  sysevent_get("NatFirewallRule") → gets count
  for i in 1..count:
    sysevent_get("NatFirewallRule_i") → gets rule string
    write rule to /tmp/.ipt
```

---

## Service Lifecycle Protocol

### Standard Service State Machine

```
                    ┌─────────┐
         ┌─────────│ stopped │◄──────────────┐
         │         └────┬────┘               │
         │              │ <service>-start     │ <service>-stop
         │              ▼                     │
         │         ┌─────────┐               │
         │         │starting │               │
         │         └────┬────┘               │
         │              │ success             │
         │              ▼                     │
         │         ┌─────────┐               │
         │    ┌───►│ started │───────────────┤
         │    │    └────┬────┘               │
         │    │         │ <service>-restart   │
         │    │         ▼                     │
         │    │    ┌──────────┐              │
         │    │    │restarting│              │
         │    │    └────┬─────┘              │
         │    │         │                    │
         │    └─────────┘                    │
         │                                   │
         │    failure at any point           │
         │         ┌─────────┐              │
         └────────►│  error  │──────────────┘
                   └─────────┘    (manual restart required)
```

### Event Registration Convention

```
Service "myservice" registers these standardized events:

1. myservice-start    → handler invoked with "start" arg
2. myservice-stop     → handler invoked with "stop" arg  
3. myservice-restart  → handler invoked with "restart" arg

Status published to: "myservice-status"
Values: "stopped" | "starting" | "started" | "stopping" | "error"

Other services depend on status:
  sysevent_get("myservice-status") == "started" → safe to interact
```

### Anti-Patterns Prevented by Design

| Anti-Pattern | Prevention Mechanism |
|---|---|
| Double-start | `wait_till_end_state()` checks transitional states |
| Stop during start | Status check before action |
| Recursive restart | Handler checks current state, no-ops if already restarting |
| Orphaned processes | PID file tracking + kill on stop |
| Race with config | Transactional commit before event fire (UTCTX) |
