# Functional Workflows

## 1. System Initialization Flow

### Phase 1: Bootstrap (utopia_init.sh)

```
System Boot
    │
    ├── 1. Kernel parameter tuning
    │   └── Set nf_conntrack timeouts, TCP buffers, network params
    │
    ├── 2. Syscfg database initialization
    │   ├── Check /nvram/syscfg.db (primary)
    │   ├── Check /nvram/syscfg.db.prev (backup)
    │   ├── If both corrupt: load from /etc/utopia/system_defaults
    │   └── syscfg_create -f <file> → creates shared memory segment
    │
    ├── 3. Factory reset detection
    │   ├── Check hardware reset button (GPIO)
    │   ├── If factory reset: wipe nvram, PSM, DHCP leases
    │   └── Reload system_defaults
    │
    ├── 4. Sysevent daemon start
    │   └── /usr/bin/syseventd --threads 10
    │       ├── Create PID file /var/run/syseventd.pid
    │       ├── Initialize TCP + UDS listeners
    │       ├── Spawn worker threads
    │       └── Ready for client connections
    │
    ├── 5. Apply system defaults
    │   └── apply_system_defaults
    │       ├── Compare current syscfg against /etc/utopia/system_defaults
    │       ├── Set missing keys to defaults
    │       └── Handle partner-specific overrides (JSON)
    │
    ├── 6. Service registration
    │   └── For each service in /etc/utopia/service.d/:
    │       sm_register(service_name, events[])
    │       → Callback handlers installed in sysevent
    │
    └── 7. Post "system-ready" event
        └── sysevent set system-status "started"
```

### Phase 2: Service Activation

```
system-status = "started"
    │
    ├── LAN services
    │   ├── service_multinet: create bridges, assign VLANs
    │   ├── service_dhcp: start dnsmasq (DHCP server + DNS proxy)
    │   └── firewall: generate and apply iptables rules
    │
    ├── WAN services
    │   ├── service_wan: configure WAN interface
    │   ├── Start DHCP client (udhcpc) on WAN
    │   └── Wait for IP address acquisition
    │
    └── Post-WAN services (triggered by wan-status = "started")
        ├── service_routed: start routing daemons
        ├── service_ipv6: configure IPv6, start dibbler
        ├── service_ddns: register with DDNS provider
        └── firewall-restart: regenerate rules with WAN IP
```

## 2. Configuration Change Flow

### User Changes a Parameter (e.g., DHCP Pool Range)

```
Step 1: External request arrives
    │  (TR-069 SetParameterValues or WebUI form submit)
    │
    ▼
Step 2: CcspPandM calls UTAPI
    │  Utopia_SetDHCPServerPool(ctx, pool_id, start_ip, end_ip)
    │
    ▼
Step 3: UTAPI buffers changes
    │  UTOPIA_SET(ctx, UtopiaValue_DHCP_Start, "192.168.1.100")
    │  UTOPIA_SET(ctx, UtopiaValue_DHCP_End, "192.168.1.200")
    │  → Added to UtopiaTransact_Node linked list
    │
    ▼
Step 4: Transaction commit (Utopia_Free)
    │  syscfg_set(NULL, "dhcp_start", "192.168.1.100")
    │  syscfg_set(NULL, "dhcp_end", "192.168.1.200")
    │  syscfg_commit()  → Write to /nvram/syscfg.db
    │
    ▼
Step 5: Event trigger
    │  sysevent_set("dhcp_server-restart", "")
    │
    ▼
Step 6: Sysevent dispatch
    │  DataMgr detects value change → TriggerMgr matches callback
    │  Fork Helper executes: /usr/bin/service_dhcp dhcp_server-restart
    │
    ▼
Step 7: Service handler executes
    │  service_dhcp:
    │  ├── Stop dnsmasq (SIGTERM)
    │  ├── Regenerate /etc/dnsmasq.conf from syscfg
    │  ├── Start dnsmasq
    │  └── sysevent_set("dhcp_server-status", "started")
    │
    ▼
Step 8: Completion propagation
    CcspPandM receives success response
```

## 3. WAN Connection Establishment

```
wan-start event received
    │
    ├── Read configuration
    │   ├── wan_proto (dhcp/static/pppoe)
    │   ├── erouter_mode (ipv4/ipv6/dual/bridge)
    │   └── wan_ifname (erouter0)
    │
    ├── Interface bringup
    │   ├── ifconfig erouter0 up
    │   ├── sysctl net.ipv4.ip_forward = 1
    │   └── sysctl accept_ra = 2 (for IPv6)
    │
    ├── Address acquisition (DHCP mode)
    │   ├── Start udhcpc on erouter0 with options:
    │   │   -i erouter0 -p /tmp/udhcpc.erouter0.pid
    │   │   -s /usr/bin/service_udhcpc
    │   │   -O 100 (DS-Lite AFTR)
    │   │
    │   └── udhcpc sends DHCPDISCOVER → DHCPOFFER → DHCPREQUEST → DHCPACK
    │
    ├── DHCP callback (service_udhcpc handle_wan)
    │   ├── Parse environment: ip, subnet, router, dns, lease, opt100
    │   ├── Configure interface: ip addr add $ip/$mask dev erouter0
    │   ├── Set default route: ip route add default via $router
    │   ├── Update resolv.conf with DNS servers
    │   ├── sysevent_set("current_wan_ipaddr", ip)
    │   ├── sysevent_set("wan_service-status", "started")
    │   └── sysevent_set("wan-status", "started")
    │
    ├── Post-connection triggers (wan-status = "started")
    │   ├── Firewall regeneration with real WAN IP
    │   ├── Routing daemon restart
    │   ├── DDNS update
    │   └── IPv6 DHCPv6 client start (if dual-stack)
    │
    └── DS-Lite handling (if option 64/100 received)
        ├── Wait for AFTR address (max 60s)
        ├── service_dslite: create ip6tnl tunnel
        └── Update routing for IPv4-over-IPv6
```

## 4. Firewall Regeneration Flow

```
firewall-restart event
    │
    ├── Acquire process-shared mutex (prevent concurrent rebuilds)
    │
    ├── Read configuration (~100+ syscfg keys)
    │   ├── WAN: ip, interface, protocol, bridge mode
    │   ├── LAN: ip, subnet, bridge interfaces
    │   ├── Features: DMZ, port_forward, port_trigger
    │   ├── Security: firewall_level, ping_block, ident_block
    │   ├── QoS: enabled, defined policies
    │   └── Parental: managed_sites, managed_services
    │
    ├── Generate IPv4 rules → /tmp/.ipt
    │   ├── *raw table (notrack for local, connection tracking bypass)
    │   ├── *mangle table (QoS DSCP marks, TTL)
    │   ├── *nat table
    │   │   ├── Port forwarding (DNAT)
    │   │   ├── DMZ (DNAT catch-all)
    │   │   ├── Port triggering rules
    │   │   ├── MASQUERADE (outbound NAT)
    │   │   └── DNS/HTTP intercept (captive portal)
    │   └── *filter table
    │       ├── INPUT: wan2self, lan2self chains
    │       ├── FORWARD: lan2wan, wan2lan chains
    │       ├── OUTPUT: self2wan chain
    │       ├── Rate limiting (SYN flood, ICMP)
    │       └── Logging rules (for dropped packets)
    │
    ├── Generate IPv6 rules → /tmp/.ipt_v6
    │
    ├── Apply atomically
    │   ├── iptables-restore < /tmp/.ipt
    │   └── ip6tables-restore < /tmp/.ipt_v6
    │
    ├── conntrack -F (flush stale connections)
    │
    ├── Release mutex
    │
    └── sysevent_set("firewall-status", "started")
```

## 5. DHCP Lease Renewal Flow

```
udhcpc receives DHCPACK (renewal)
    │
    ├── udhcpc invokes script: service_udhcpc renew
    │
    ├── handle_wan() compares new lease with current:
    │   ├── IP unchanged: update lease time only
    │   ├── IP changed:
    │   │   ├── Remove old IP from interface
    │   │   ├── Add new IP
    │   │   ├── Update routes
    │   │   ├── sysevent_set("current_wan_ipaddr", new_ip)
    │   │   └── Trigger firewall-restart (rules reference WAN IP)
    │   │
    │   ├── DNS changed:
    │   │   ├── Update /etc/resolv.conf
    │   │   └── sysevent_set("wan_dns", new_dns)
    │   │
    │   └── Router/gateway changed:
    │       ├── Update default route
    │       └── sysevent_set("default_router", new_gw)
    │
    └── Continue normal operation
```

## 6. IPv6 Prefix Delegation Flow

```
DHCPv6 client receives IA_PD (prefix delegation)
    │
    ├── Client stores prefix info in sysevent:
    │   sysevent_set("tr_erouter0_dhcpv6_client_v6pref", "2001:db8:1::/48")
    │   sysevent_set("tr_erouter0_dhcpv6_client_v6pref_vtime", "3600")
    │
    ├── service_ipv6 receives event → serv_ipv6_start()
    │
    ├── Topology mode determines sub-prefix allocation:
    │   ├── FAVOR_DEPTH: longer prefixes (/64) per LAN interface
    │   └── FAVOR_WIDTH: more /64 networks from available space
    │
    ├── For each LAN bridge (brlan0, brlan1, ...):
    │   ├── Calculate sub-prefix from delegated prefix
    │   ├── Assign ::1 address on bridge interface
    │   ├── sysevent_set("ipv6_<bridge>_prefix", sub_prefix)
    │   └── Fire lan_addr6_set event
    │
    ├── Configure DHCPv6 server (dibbler-server):
    │   ├── Generate /etc/dibbler/server.conf
    │   ├── Set IA_NA/IA_PD pools from delegated prefix
    │   └── Restart dibbler-server
    │
    └── Configure Router Advertisement:
        ├── Generate radvd.conf with prefix info
        └── Restart radvd → LAN clients get IPv6 via SLAAC
```

## 7. Service Recovery Flow

```
pmon detects process death
    │
    ├── Read config: "<process> <pidfile> <restart_cmd>"
    │
    ├── Verify death:
    │   ├── Read PID from pidfile
    │   ├── Check /proc/<pid>/cmdline
    │   └── If process alive: skip (false alarm)
    │
    ├── If confirmed dead:
    │   ├── Log to /rdklogs/logs/SelfHeal.txt.0
    │   ├── Send telemetry event
    │   └── Execute restart command via fork()+execl()
    │
    └── Service restarts → registers with sysevent → resumes operation

Sysevent sanity thread (blocked process recovery):
    │
    ├── Check every 5s: any fork_helper child blocked > 300s?
    │
    ├── If blocked:
    │   ├── kill(blocked_pid, SIGKILL)
    │   ├── Remove from blocked list
    │   └── Log "killed blocked process <pid>"
    │
    └── Continues monitoring
```

## 8. Multi-Network (Bridge/VLAN) Setup

```
multinet-up event (instance N)
    │
    ├── Read instance config from syscfg/PSM:
    │   ├── Bridge name (e.g., brlan0)
    │   ├── Member interfaces
    │   ├── VLAN IDs
    │   └── IP configuration
    │
    ├── Create bridge:
    │   ├── brctl addbr brlan<N>
    │   └── Configure bridge parameters (STP, aging)
    │
    ├── Add member interfaces:
    │   ├── For each member configured:
    │   │   ├── Create VLAN interface if needed (vconfig add)
    │   │   └── brctl addif brlan<N> <interface>
    │   └── Handle platform-specific (Puma6/7, BCM)
    │
    ├── Assign IP:
    │   └── ifconfig brlan<N> <ip> netmask <mask> up
    │
    ├── Fire status event:
    │   └── sysevent_set("multinet_<N>-status", "ready")
    │
    └── Dependent services activate:
        ├── DHCP server starts for pool on brlan<N>
        └── Firewall adds rules for new interface
```

## 9. Device Mode Switching (Router ↔ Extender)

```
DeviceMode update event (0=Router, 1=Extender)
    │
    ├── Stop services of OLD mode:
    │   ├── sysevent_set("lan-stop")
    │   ├── ipv4-down for all LAN instances
    │   ├── Kill zebra, CcspLMLite
    │   └── Stop NAT/routing services
    │
    ├── Start services of NEW mode:
    │   ├── sysevent_set("lan-start")
    │   ├── ipv4-up for appropriate instances
    │   ├── lnf-setup (Lost-and-Found network)
    │   ├── dhcp_server-restart
    │   └── firewall-restart
    │
    └── Mode fully switched
        └── Normal operation in new mode
```
