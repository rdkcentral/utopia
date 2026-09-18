# Utopia Component Overview

## Purpose

Utopia is the foundational system infrastructure component for RDK-B (Reference Design Kit - Broadband) middleware. It provides system initialization, configuration management, inter-process communication (IPC) via an event bus, and network service orchestration for residential gateway devices.

## Core Responsibilities

| Responsibility | Description |
|---|---|
| **Configuration Persistence** | Shared-memory-based key-value store (syscfg) with filesystem backing |
| **Event Bus IPC** | Publish-subscribe messaging (sysevent) over Unix domain sockets |
| **Network Service Orchestration** | Coordinated management of DHCP, firewall, routing, WAN, IPv6 |
| **Unified API Layer** | UTAPI/UTCTX libraries abstracting config and event access |
| **Service Lifecycle** | Start/stop/restart coordination for all managed services |
| **Process Monitoring** | Health checks and auto-restart via pmon |

## Module Inventory

| Module | Type | Purpose |
|--------|------|---------|
| `syscfg` | Library + Daemon | Persistent configuration database (shared memory + file) |
| `sysevent` | Daemon + Library | Real-time event bus with trigger-based action execution |
| `utapi` | Library + CLI | High-level configuration API (typed getters/setters) |
| `utctx` | Library | Transaction context manager over syscfg/sysevent |
| `firewall` | Service binary | iptables/ip6tables rule generation and management |
| `service_dhcp` | Service binary | DHCP server lifecycle (dnsmasq management) |
| `service_wan` | Service binary | WAN interface and DHCP client management |
| `service_routed` | Service binary | Routing daemon management (zebra/ripd, radvd) |
| `service_ipv6` | Service binary | IPv6 provisioning and DHCPv6 server (dibbler) |
| `service_multinet` | Service binary | VLAN/bridge management and network isolation |
| `service_udhcpc` | Service binary | DHCP client callback handler |
| `service_ddns` | Service binary | Dynamic DNS registration with external providers |
| `service_dslite` | Service binary | DS-Lite (IPv4-in-IPv6) tunnel management |
| `service_deviceMode` | Service binary | Router/Extender mode switching |
| `trigger` | Daemon | Port-range triggering via netfilter queue |
| `pmon` | Service binary | Process health monitor with auto-restart |
| `newhost` | Service binary | New LAN host detection and firewall trigger |
| `macclone` | Service binary | WAN interface MAC address cloning |
| `ulog` | Library | Unified logging (wraps syslog with component tags) |
| `pal` | Library | Platform Abstraction Layer (network, UPnP, XML) |
| `services/lib` | Library | Service registration framework (srvmgr) |
| `util` | Library | Shared utilities (vsystem, iface ops, PSM access) |
| `scripts/init` | Shell scripts | System bootstrap and service initialization |
| `walled_garden` | Shell scripts | Guest/parental-control access aging |

## Key Interfaces

### Northbound (consumed by other RDK-B components)
- **UTAPI C API** — typed configuration access for CCSP components
- **syscfg CLI** — command-line configuration read/write
- **sysevent CLI** — command-line event publish/subscribe
- **RBus** — enhanced message bus integration (optional)

### Southbound (consumed by Utopia)
- **Linux kernel** — iptables, ip route, netlink, /proc, /sys
- **HAL APIs** — wifi_hal, ethernet_hal, docsis_hal, platform_hal
- **External daemons** — dnsmasq, udhcpc, dibbler-server, zebra, ripd, radvd, curl

### Lateral (IPC between Utopia modules)
- **Sysevent bus** — all inter-service coordination
- **Syscfg shared memory** — cross-process configuration access
- **Pipes/FIFOs** — syseventd internal worker communication

## Platform Support

Utopia supports multiple hardware platforms via compile-time configuration:

| Platform | Flag | Notes |
|----------|------|-------|
| Intel USG (Puma6) | `--with-ccsp-platform=intel_usg` | Legacy Puma6 devices |
| Intel Puma7 | `--with-ccsp-platform=intel_puma7` | XB6/XB7 platforms |
| Broadcom | `--with-ccsp-platform=bcm` | BCM-based gateways |
| PC (emulation) | `--with-ccsp-platform=pc` | Development/testing |

## Build System

- **Autotools** (autoconf/automake/libtool)
- Conditional compilation via `AM_CONDITIONAL` flags
- Feature flags: DSLite, CoreNetLib, Extender, Hotspot, DDNS, MoCA
