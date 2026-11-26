# AI Prompts for Utopia Debugging & Development

## Debugging Prompts

### Prompt: Diagnose Service Failure
```
Context: Utopia is the RDK-B system infrastructure component managing configuration (syscfg), events (sysevent), and network services (DHCP, firewall, WAN, routing, IPv6).

Task: Diagnose why [SERVICE_NAME] is not functioning correctly.

Available Information:
- Service status: [sysevent get <service>-status output]
- Relevant logs: [paste log excerpt]
- System state: [describe current behavior]

Analysis Framework:
1. Check service state machine: Is it stuck in a transitional state (starting/stopping)?
2. Check dependencies: Are upstream services ready? (sysevent get system-status, wan-status, lan-status)
3. Check configuration: Are required syscfg keys set and valid?
4. Check external daemons: Are dependent processes (dnsmasq, udhcpc, dibbler) running?
5. Check resources: Is shared memory accessible? Are FD limits hit?

Provide: Root cause hypothesis, verification commands, and resolution steps.
```

### Prompt: Analyze Firewall Issue
```
Context: Utopia firewall generates iptables/ip6tables rules from syscfg configuration and applies atomically via iptables-restore. It uses a process-shared mutex (PTHREAD_PROCESS_SHARED + PTHREAD_MUTEX_ROBUST) at /tmp/firewall_mutex.

Task: Analyze why [describe traffic issue - blocked/allowed incorrectly].

Information needed:
- firewall-status value (sysevent get firewall-status)
- Current WAN IP (sysevent get current_wan_ipaddr)
- Generated rules (/tmp/.ipt content relevant section)
- Active rules (iptables -L <relevant_chain> -n)
- Relevant syscfg entries (port forwarding, DMZ, firewall level)

Analysis:
1. Was the rule generated? (check /tmp/.ipt)
2. Was it applied? (check iptables -L vs file content)
3. Is there a conflicting rule earlier in the chain?
4. Is conntrack holding stale state?
5. Is the mutex preventing regeneration?
```

### Prompt: Trace Event Flow
```
Context: Sysevent is the IPC bus. When a value is set, DataMgr detects the change, TriggerMgr looks up registered callbacks, and either sends a notification message to connected clients or executes an external binary via Fork Helper.

Task: Trace why event [EVENT_NAME] is not triggering expected action.

Debug sequence:
1. Verify event was set: sysevent get [EVENT_NAME]
2. Check sysevent tracer: grep EVENT_NAME /rdklogs/logs/sysevent_tracer.txt
3. Verify trigger registration: look for async_id storage (xsm_<service>_async_id_<event>)
4. Check worker thread health: are workers blocked? (sanity thread kills after 300s)
5. Check fork helper: is the target binary accessible and executable?
6. Check handler output: did the invoked handler produce errors?

Expected flow: SET → DataMgr change detect → TriggerMgr dispatch → Worker sends to Fork Helper → Fork Helper fork+exec → Handler runs
```

## RCA Prompts

### Prompt: Root Cause Analysis Template
```
Context: Utopia component failure requiring root cause analysis.

Failure: [Describe the failure]
Impact: [P1/P2/P3 + user-visible impact]
Timeline: [When first observed, duration]

RCA Framework:
1. TIMELINE RECONSTRUCTION
   - First anomaly timestamp in logs
   - Sequence of events leading to failure
   - Cascading effects on dependent services

2. STATE ANALYSIS
   - Expected state vs actual state at failure point
   - Last known good state and transition that broke it
   - Dependency states at time of failure

3. CODE PATH IDENTIFICATION
   - Which source file/function was executing
   - What conditional branch was taken
   - What error code was returned/logged

4. ROOT CAUSE CLASSIFICATION
   - Configuration error (wrong syscfg value)
   - Race condition (timing between events)
   - Resource exhaustion (FDs, memory, disk)
   - External dependency failure (daemon crash, HAL error)
   - Code defect (logic error, missing error handling)

5. PREVENTION
   - What check/guard would have prevented this
   - What monitoring would have detected it earlier
```

## Feature Development Prompts

### Prompt: Implement New Service
```
Context: Utopia services follow a standard pattern: event-driven command dispatch with sysevent/syscfg integration. Each service is a separate binary invoked by sysevent callbacks.

Task: Design and implement a new service for [FEATURE_DESCRIPTION].

Implementation checklist:
1. Define service name and events:
   - <service>-start, <service>-stop, <service>-restart
   - Custom events this service responds to
   - Events this service publishes

2. Define configuration keys (syscfg):
   - What parameters does the service need?
   - What are sensible defaults?
   - Add to system_defaults file

3. Implement using standard pattern:
   - State structure (sefd, setok, + custom fields)
   - Command dispatch table (cmd_ops[])
   - Handler functions for each operation
   - Status transitions (stopped → starting → started)
   - Error handling with appropriate logging

4. Register with build system:
   - Create source/service_<name>/Makefile.am
   - Add to source/Makefile.am SUBDIRS
   - Add AC_CONFIG_FILES in configure.ac
   - Consider conditional compilation (AM_CONDITIONAL)

5. Register with sysevent:
   - Add callback registration (via srvmgr or service script)
   - Define trigger event dependencies

6. Test:
   - Manual: sysevent set <service>-start; check status transitions
   - Verify: dependent services notified on state changes
   - Error cases: missing config, dependency unavailable
```

### Prompt: Add Configuration Parameter
```
Context: Utopia configuration flows through syscfg (persistent) or sysevent (runtime). UTAPI provides typed access, and UTCTX manages transaction semantics.

Task: Add new configuration parameter [PARAM_NAME] for [PURPOSE].

Steps:
1. Choose storage type:
   - Persistent (survives reboot): syscfg → add to system_defaults
   - Runtime (transient): sysevent → no persistence needed

2. If UTAPI access needed:
   - Add enum value to UtopiaValue enum in utctx headers
   - Add entry to g_Utopia[] table in utctx.c with:
     - Type (Config/IndexedConfig/Event/NamedConfig)
     - Key format string
     - Namespace (NULL for global)
     - Event flags (which events to fire on change)
   - Add getter/setter in utapi.c

3. Add to system_defaults:
   - Format: "key=default_value"
   - Will be applied on first boot or factory reset

4. Consuming service:
   - syscfg_get(NULL, "param_name", buf, sizeof(buf))
   - React to change event (register callback via sysevent)
```
