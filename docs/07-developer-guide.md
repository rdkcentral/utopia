# Developer Guide

## Build & Development Setup

### Prerequisites
- GCC cross-compiler for target platform
- Autotools (autoconf >= 2.65, automake, libtool)
- Libraries: libsafec, libdbus-1, libnetfilter_queue, libcjson
- RDK-B SDK with HAL headers

### Build Commands
```bash
# Generate configure script
./autogen.sh

# Configure for target platform
./configure --with-ccsp-platform=bcm \
            --enable-dslite_feature_support \
            --enable-core_net_lib_feature_support \
            --host=arm-rdk-linux-gnueabi

# Build
make -j$(nproc)

# Install to staging
make install DESTDIR=/path/to/staging
```

### Key Build Flags

| Flag | Effect |
|---|---|
| `--with-ccsp-platform=<plat>` | Platform selection (intel_usg, intel_puma7, bcm, pc) |
| `--enable-dslite_feature_support` | Include DS-Lite tunnel service |
| `--enable-core_net_lib_feature_support` | Include service_dhcp + DHCPv6 client |
| `--enable-extender` | Include device mode switching |
| `--enable-hotspot` | Include HotSpot captive portal support |
| `--enable-ddns_binary_client_support` | Include DDNS service |
| `--enable-unitTestDockerSupport` | Enable unit test build |

## Code Organization

```
source/
├── syscfg/          # Configuration database (library + CLI)
│   ├── lib/         # libsyscfg.so (shared memory hash table)
│   └── cmd/         # syscfg CLI tool
├── sysevent/        # Event bus system
│   ├── server/      # syseventd daemon (main, clients, triggers, data)
│   ├── lib/         # libsysevent.so (client API)
│   ├── control/     # sysevent CLI tool
│   ├── proxy/       # Event proxy for remote access
│   └── fork_helper/ # Child process executor
├── utapi/           # High-level configuration API
│   ├── lib/         # libutapi.so
│   └── cmd/         # utapi CLI tool
├── utctx/           # Transaction context manager
│   ├── lib/         # libutctx.so
│   └── bin/         # utctx utilities
├── firewall/        # Firewall rule generator (binary)
├── service_dhcp/    # DHCP server management
├── service_wan/     # WAN interface management
├── service_routed/  # Routing daemon management
├── service_ipv6/    # IPv6 service management
├── service_multinet/# Bridge/VLAN management
├── service_udhcpc/  # DHCP client callback handler
├── service_ddns/    # Dynamic DNS service
├── service_dslite/  # DS-Lite tunnel service
├── service_deviceMode/ # Router/Extender mode switching
├── trigger/         # NFQ port triggering daemon
├── pmon/            # Process monitor
├── newhost/         # New host detection
├── macclone/        # MAC address cloning
├── ulog/            # Unified logging library
├── pal/             # Platform abstraction layer
├── services/lib/    # Service registration framework (srvmgr)
├── util/            # Shared utilities
├── scripts/init/    # Boot scripts and service handlers
└── walled_garden/   # Guest/parental access aging scripts
```

## Coding Patterns

### Adding a New Service

1. Create directory: `source/service_myfeature/`
2. Implement main with standard pattern:

```c
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include "util.h"

struct serv_myfeature {
    int sefd;    // sysevent file descriptor
    int setok;   // sysevent token
    // service-specific state
};

static int myfeature_start(struct serv_myfeature *sf) {
    // Read config from syscfg
    // Apply configuration
    // Start external daemon if needed
    sysevent_set(sf->sefd, sf->setok, "myfeature-status", "started", 0);
    return 0;
}

static int myfeature_stop(struct serv_myfeature *sf) {
    sysevent_set(sf->sefd, sf->setok, "myfeature-status", "stopping", 0);
    // Stop daemon, cleanup
    sysevent_set(sf->sefd, sf->setok, "myfeature-status", "stopped", 0);
    return 0;
}

static struct cmd_op {
    const char *name;
    int (*handler)(struct serv_myfeature *);
} cmd_ops[] = {
    {"start",   myfeature_start},
    {"stop",    myfeature_stop},
    {"restart", myfeature_restart},
};

int main(int argc, char *argv[]) {
    struct serv_myfeature sf;
    
    sf.sefd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT,
                            SE_VERSION, "myfeature", &sf.setok);
    if (sf.sefd < 0) return -1;
    
    // Dispatch command
    for (int i = 0; i < ARRAY_SIZE(cmd_ops); i++) {
        if (strcmp(argv[1], cmd_ops[i].name) == 0) {
            cmd_ops[i].handler(&sf);
            break;
        }
    }
    
    sysevent_close(sf.sefd, sf.setok);
    return 0;
}
```

3. Create `Makefile.am` and add to `source/Makefile.am` SUBDIRS
4. Add `AC_CONFIG_FILES` entry in `configure.ac`
5. Register with sysevent (in service script or apply_system_defaults)

### Sysevent Event Naming Convention

```
<service>-start     → Request service start
<service>-stop      → Request service stop
<service>-restart   → Request service restart
<service>-status    → Service state (stopped/starting/started/stopping/error)
<resource>-up       → Resource became available
<resource>-down     → Resource became unavailable
current_<param>     → Runtime parameter value (e.g., current_wan_ipaddr)
```

### Syscfg Key Naming Convention

```
<feature>_<parameter>         → e.g., dhcp_start, wan_proto
<feature>_<param>_<index>     → e.g., StaticRoute_1, PortForward_3
<namespace>::<key>            → Namespaced keys for isolation
```

## Logging

### Log Levels and Files

| Log Target | Path | Content | Verbosity Control |
|---|---|---|---|
| System syslog | `/var/log/messages` | All ulog output | syslog config |
| Console log | `/rdklogs/logs/Consolelog.txt.0` | Service operations | Always on |
| Firewall debug | `/rdklogs/logs/FirewallDebug.txt` | Rule generation detail | Compile flag |
| MultiNet debug | `/rdklogs/logs/MnetDebug.txt` | Bridge operations | Always on |
| Sysevent trace | `/rdklogs/logs/sysevent_tracer.txt` | Event flow tracing | Runtime flag |
| SelfHeal | `/rdklogs/logs/SelfHeal.txt.0` | Process recovery events | Always on |

### Adding Logging to Your Code

```c
#include <ulog/ulog.h>

// Standard logging (goes to syslog)
ulog(ULOG_SYSTEM, UL_INFO, "service started successfully");
ulogf(ULOG_SYSTEM, UL_INFO, "configured %s with IP %s", ifname, ip);

// Error logging
ulog_error(ULOG_SYSTEM, UL_MYSERVICE, "failed to open config file");
ulog_errorf(ULOG_SYSTEM, UL_MYSERVICE, "syscfg_get failed for key: %s", key);

// Debug (only when enabled)
ulog_debug(ULOG_SYSTEM, UL_MYSERVICE, "entering state: CONNECTED");
```

### Telemetry Events

```c
#include <telemetry_busmessage_sender.h>

// Send telemetry marker
t2_event_d("SYS_SH_RDKB_FIREWALL_RESTART", 1);
t2_event_s("WAN_INFO_IPAddress", wan_ip);
```

## Debug Commands

### Runtime Inspection

```bash
# Sysevent state inspection
sysevent get wan-status                    # Check WAN state
sysevent get dhcp_server-status            # Check DHCP state
sysevent get firewall-status               # Check firewall state
sysevent get system-status                 # Check system state

# Configuration inspection
syscfg get wan_proto                       # WAN protocol (dhcp/static)
syscfg get dhcp_start                      # DHCP pool start
syscfg get lan_ipaddr                      # LAN IP address
syscfg show | grep firewall               # All firewall config

# Service status
sysevent get multinet_1-status             # Bridge instance status
sysevent get ipv4_4-status                 # IPv4 instance status
```

### Forcing Service Operations

```bash
# Restart specific services
sysevent set dhcp_server-restart
sysevent set firewall-restart
sysevent set wan-restart
sysevent set service_ipv6-restart

# Force interface reconfiguration
sysevent set multinet_1-up
sysevent set ipv4-up 4

# Reset stuck states
sysevent set dhcp_server-status stopped
sysevent set firewall-status stopped
```

### Network Diagnostics

```bash
# Interface status
ip addr show                              # All interface IPs
ip link show                              # Interface states
brctl show                                # Bridge configuration
cat /sys/class/net/erouter0/carrier       # Physical link

# Routing
ip route show                             # IPv4 routes
ip -6 route show                          # IPv6 routes
ip rule show                              # Policy routing

# Firewall
iptables -L -n -v                         # IPv4 rules with counters
ip6tables -L -n -v                        # IPv6 rules
iptables -t nat -L -n                     # NAT rules
cat /proc/net/nf_conntrack | wc -l        # Connection count

# DNS/DHCP
cat /etc/dnsmasq.conf                     # DHCP server config
cat /tmp/dnsmasq.leases                   # Active leases
cat /etc/resolv.conf                      # DNS configuration
```

## Validation Steps

### After Modifying Syscfg Logic
1. `syscfg set test_key test_value && syscfg commit`
2. `syscfg get test_key` → should return "test_value"
3. Reboot → `syscfg get test_key` → still "test_value"
4. Check `/nvram/syscfg.db` contains the entry

### After Modifying Sysevent Logic
1. Terminal 1: `sysevent async test_event`
2. Terminal 2: `sysevent set test_event hello`
3. Terminal 1 should receive notification
4. Verify trigger execution with tracer log

### After Modifying a Service
1. `sysevent set <service>-restart`
2. Check `sysevent get <service>-status` transitions: stopped → starting → started
3. Verify functional behavior (e.g., DHCP lease acquisition)
4. Check no error logs in `/rdklogs/logs/Consolelog.txt.0`

### After Modifying Firewall Rules
1. `sysevent set firewall-restart`
2. `sysevent get firewall-status` → "started"
3. `iptables -L -n | wc -l` → rule count reasonable
4. Test: ping external host, verify port forwarding
5. Check `/rdklogs/logs/FirewallDebug.txt` for errors

## Unit Testing

Unit tests are available under `source/test/` when built with `--enable-unitTestDockerSupport`:

```bash
# Build with tests
./configure --enable-unitTestDockerSupport ...
make

# Test directories
source/test/service_routed/
source/test/service_ipv6/
source/test/service_udhcpc/
source/test/service_dhcp/
source/test/service_wan/
source/test/apply_system_defaults/
```

Tests use mocked sysevent/syscfg to validate service logic without hardware.

## Common Pitfalls

1. **SIGCHLD handling**: Services invoked by syseventd inherit `SIG_IGN` for SIGCHLD. Reset to `SIG_DFL` before calling `system()` or forks will return -1.

2. **Sysevent connection leaks**: Always close sysevent connection in error paths. Leaked FDs exhaust the client table.

3. **Syscfg commit frequency**: Don't commit after every set. Batch changes, then commit once (reduces flash wear).

4. **Event loops**: Don't trigger your own event recursively (e.g., firewall-restart handler must not trigger firewall-restart).

5. **Shared memory alignment**: When modifying syscfg hash table structures, ensure all offsets are properly aligned for the target architecture.

6. **Process mutex recovery**: If using shared-memory mutexes (like firewall), always handle EOWNERDEAD.
