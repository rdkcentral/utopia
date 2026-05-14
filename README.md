# Utopia Documentation

Utopia serves as the foundational system infrastructure component for RDK-B middleware, providing comprehensive system initialization, configuration management, event bus services, and network service orchestration. This component acts as the backbone that enables inter-process communication, persistent configuration storage, and coordinated startup/shutdown sequences across all RDK-B middleware components.

Utopia provides three critical service layers to the RDK-B stack: 
* **System Infrastructure Services** that handle system initialization, configuration persistence (syscfg), and inter-component messaging (sysevent); 
* **Network Service Management** that orchestrates networking services including DHCP, firewall, routing, and WAN connectivity; and 
* **API Layer Services** that expose standardized interfaces (UTAPI) for configuration management and system control to other RDK-B components and external management systems.

The component integrates deeply with the Linux system layer through direct HAL interactions, manages persistent data through filesystem-based storage mechanisms, and coordinates with other RDK-B components via RBus messaging protocol. Utopia's modular architecture supports platform-specific customizations while maintaining consistent service interfaces across different RDK-B device implementations.


```mermaid
graph LR

    subgraph "External Systems"
        RemoteMgmt["Remote Management"]
        LocalUI["Local Web UI"]
    end

    
    subgraph "RDK-B Platform"
        subgraph "Remote Management Agents"
            ProtocolAgents["Protocol Agents<br>( TR-069, WebPA, USP etc.)"]
        end
        rdkbComponent["Other RDK-B Components"]
        subgraph "Utopia"
            subgraph "Utopia Core Services"
                SysEvent[SysEvent Bus]
                SysCfg[SysCfg Storage] 
                ServiceMgr[Service Manager]
                UtAPI[UTAPI Library]
            end
    
            subgraph "Utopia Network Services"
                DHCP[DHCP Service]
                Firewall[Firewall Service]
                Routing[Routing Service]
                MultiNet[Multi-Network Service]
                WAN[WAN Service]
                IPv6[IPv6 Service]
                IGD[UPnP IGD]
            end
        end
        subgraph "Platform Layer"
            HAL["Platform HAL"]
            Linux["Linux"]
            NetFilter[NetFilter/IPTables]
        end
    end

    RemoteMgmt --> ProtocolAgents
    LocalUI --> UtAPI
    ProtocolAgents --> SysEvent
    rdkbComponent --> SysCfg
    
    UtAPI --> SysCfg
    UtAPI --> SysEvent
    ServiceMgr --> SysEvent
    
    SysEvent --> DHCP
    SysEvent --> Firewall
    SysEvent --> Routing
    SysEvent --> MultiNet
    SysEvent --> WAN
    SysEvent --> IPv6
    SysEvent --> IDG
    
    SysCfg --> DHCP
    SysCfg --> Firewall
    SysCfg --> WAN
    
    Routing --> Linux
    Firewall --> NetFilter
    DHCP --> HAL
    WAN --> HAL
    HAL --> Linux

    classDef external fill:#fff3e0,stroke:#ef6c00,stroke-width:2px;
    classDef utopia fill:#e3f2fd,stroke:#1976d2,stroke-width:3px;
    classDef rdkbComponent fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px;
    classDef system fill:#fce4ec,stroke:#c2185b,stroke-width:2px;

    class RemoteMgmt,LocalUI external;
    class SysEvent,SysCfg,ServiceMgr,UtAPI,DHCP,Firewall,Routing,MultiNet,WAN,IPv6,IGD utopia;
    class ProtocolAgents,rdkbComponent, rdkbComponent;
    class HAL,Linux,NetFilter system;
```


**Key Features & Responsibilities**: 

- **System Infrastructure Management**: Provides core system initialization services including process startup coordination, dependency management, and system-wide configuration bootstrapping essential for RDK-B middleware operation 
- **Configuration Persistence (syscfg)**: Implements a high-performance shared memory-based configuration database with filesystem backing that enables atomic configuration updates and fast parameter retrieval across all system components 
- **Inter-Process Event Bus (sysevent)**: Operates a publish-subscribe event messaging system using Unix domain sockets that facilitates real-time communication and state synchronization between RDK-B middleware components 
- **Network Service Orchestration**: Manages and coordinates networking services including DHCP server/client operations, firewall rule management, routing table updates, and WAN interface configuration through integrated service handlers 
- **Unified API Layer (UTAPI)**: Exposes standardized C APIs and command-line interfaces for system configuration, network management, and status monitoring that abstract platform-specific implementations from higher-level components 
- **Multi-Network Management**: Provides advanced networking capabilities including VLAN management, bridge configuration, multi-WAN support, and service-specific network isolation through the service_multinet framework 


## Design

Utopia's architectural design follows a layered service-oriented approach that separates system infrastructure from application-specific networking logic. The core design principle centers around three foundational services: syscfg for configuration persistence, sysevent for inter-process communication, and UTAPI for external interface abstraction. These services operate as independent but coordinated daemons that provide reliable, high-performance infrastructure for the entire RDK-B middleware stack.

The design emphasizes scalability and maintainability through modular service decomposition, where each networking function (DHCP, firewall, routing) operates as an independent service process that communicates through standardized IPC mechanisms. Configuration changes propagate through the sysevent bus, triggering coordinated updates across dependent services without requiring direct inter-service dependencies. The shared memory-based syscfg implementation ensures configuration consistency while providing sub-millisecond access times critical for real-time networking operations.

Integration with external systems occurs through well-defined interface boundaries: northbound interactions with CCSP components use RBus messaging protcol, while southbound interactions with HAL and kernel services use direct API calls and system interfaces. The UTAPI layer provides configuration abstraction that enables platform-specific implementations while maintaining API compatibility across different hardware platforms. Event-driven service activation ensures efficient resource utilization and rapid response to network state changes.

Data persistence operates through a hybrid approach combining in-memory performance with filesystem reliability, where syscfg maintains active configuration in shared memory while asynchronously committing changes to persistent storage. The sysevent system supports both persistent and transient event states, enabling appropriate handling of both configuration changes and runtime status updates. Service startup orchestration follows dependency chains defined through sysevent triggers, ensuring proper initialization ordering without hard-coded dependencies.



```mermaid
%%{init: {"flowchart": {"curve": "basis", "rankSpacing": 50, "nodeSpacing": 40}}}%%
flowchart LR

    subgraph UtopiaCore["Utopia Core"]
        %% --- UTAPI Layer ---
        subgraph UTAPI_Layer["UTAPI Layer"]
            direction TB
            UTAPI[UTAPI Library]
            UTCtx[UT Context Manager]
        end

        %% --- Core Infrastructure ---
        subgraph Core_Infra["Core Infrastructure"]
            direction TB
            SysCfg[SysCfg Service]
            SysEvent[SysEvent Daemon]
            SrvMgr[Service Manager]
        end

        %% --- Network Services ---
        subgraph Net_Services["Network Services"]
            direction TB
            DHCP[service_dhcp]
            FW[Firewall Service]
            WAN[service_wan]
            MNet[service_multinet]
            Route[service_routed]
            IPv6[service_ipv6]
            IGD[UPnP IGD]
        end

        %% --- Utility Services ---
        subgraph Util_Services["Utility Services"]
            direction TB
            DevMode[service_deviceMode]
            DDNS[service_ddns]
            DSLite[service_dslite]
            UDHCPc[service_udhcpc]
        end
    end
    %% --- Storage & IPC ---
    subgraph Storage_IPC["Storage & IPC"]
        direction LR
        SharedMem[(Shared Memory)]
        EventBus[(Event Bus)]
        ConfigFiles[(Config Files)]
    end

    %% --- Main Flows ---
    UTAPI --> UTCtx
    UTCtx --> SysCfg
    UTCtx --> SysEvent
    SrvMgr --> SysEvent

    SysCfg --> SharedMem
    SysCfg --> ConfigFiles
    SysEvent --> EventBus

    %% --- Network Services Connections ---
    Net_Services --> SysCfg
    Net_Services --> SysEvent

    %% --- Utility Services Connections ---
    Util_Services --> SysEvent
```

### Prerequisites and Dependencies

**Build-Time Flags and Configuration:**

| Configure Option | DISTRO Feature | Build Flag | Purpose | Default |
|------------------|----------------|------------|---------|---------|
| `--enable-dslite_feature_support` | `dslite` | `DSLITE_FEATURE_SUPPORT` | Enable DS-Lite dual-stack lite tunneling support | Enabled |
| `--enable-core_net_lib_feature_support` | `core-net-lib` | `CORE_NET_LIB_FEATURE_SUPPORT` | Enable advanced core networking library support | Disabled |
| `--enable-extender` | `extender` | `FEATURE_RDKB_EXTENDER` | Enable WiFi extender/mesh device support | Disabled |
| `--enable-hotspot` | N/A | `ENABLE_HOTSPOT_SERVICE` | Enable HotSpot captive portal functionality | Enabled |

**RDK-B Platform and Integration Requirements:** 

- **RDK-B Components**: CcspCommonLibrary, RBus messaging , persistent storage manager
- **HAL Dependencies**: Network HAL interfaces (WiFi, Ethernet, MoCA, DOCSIS)
- **Systemd Services**: Basic Linux systemd environment, Unix domain socket support, cron service integration
- **Message Bus**: RBus infrastructure for enhanced IPC performance (optional, falls back to direct calls)
- **Configuration Files**: `/etc/utopia/system_defaults`, `/nvram/syscfg.db`, `/etc/utopia/service.d/` service scripts
- **Startup Order**: Must initialize before CCSP components (PAM, PSM, TR-069 PA) that depend on configuration services


**Threading Model:** 

Utopia employs a hybrid threading architecture that combines single-threaded event processing with multi-threaded I/O operations to ensure data consistency while maintaining responsiveness. The core sysevent daemon operates as a single-threaded event loop that processes all IPC messages sequentially, preventing race conditions in event ordering and state management. Network service handlers typically run as separate single-threaded processes that respond to sysevent triggers, enabling isolated failure domains and simplified debugging.

- **Threading Architecture**: Hybrid - Single-threaded for event processing, Multi-threaded for I/O operations 
- **Main Thread**: Sysevent daemon main thread handles Unix domain socket connections, event routing, and client management using select()-based I/O multiplexing 
- **Main worker Threads**: 
    - **I/O Worker Threads**: Handle file system operations for syscfg persistence, preventing blocking on main event processing thread   
    - **Network Service Threads**: Separate processes for DHCP, firewall, and routing services, each with dedicated single-threaded event handlers 
- **Synchronization**: Shared memory access uses POSIX semaphores and memory barriers, sysevent uses Unix domain socket message queuing for thread-safe communication 

### Component State Flow

**Initialization to Active State**

Utopia follows a carefully orchestrated multi-phase initialization sequence that establishes core infrastructure services before activating network-specific services. The initialization process ensures dependency satisfaction and proper resource allocation while providing failure recovery mechanisms at each phase.

```mermaid
sequenceDiagram
    autonumber
    participant System
    participant Syscfg
    participant Sysevent  
    participant UTAPI
    participant Services
    participant Monitor

    System->>System: Start [*] → SystemInit
    Note right of System: Load system defaults<br>Initialize logging<br>Create shared memory<br>Set up IPC sockets

    System->>Syscfg: Boot/Service Start → SyscfgInit
    Note right of Syscfg: Initialize shared memory<br>Load persistent config<br>Setup syscfg database

    Syscfg->>Sysevent: Initialize Configuration Storage → SyseventInit
    Note right of Sysevent: Create Unix domain socket<br>Initialize event routing<br>Setup trigger manager

    Sysevent->>UTAPI: Start Event Bus → UtapiInit
    UTAPI->>Services: Initialize API Layer → ServiceRegistration
    Services->>System: Register Network Services → DependencyCheck

    System->>System: Validate Dependencies → Active
    Note right of System: Process events<br>Handle configuration<br>Monitor services<br>Respond to requests

    System->>System: Configuration Update → ConfigChange
    System->>Services: Affected Service Restart → ServiceRestart
    Services->>System: Service Synchronized → Active

    System->>System: Interface State Change → NetworkEvent
    System->>Monitor: Service Health Check Failed → FailureDetected
    Monitor->>System: Restart Failed Service → ServiceRecovery
    System->>System: Service Restored → Active

    System->>System: Stop Request → Shutdown → [*]
```

**Runtime State Changes and Context Switching**

Utopia dynamically adapts to runtime conditions through event-driven state transitions that handle network topology changes, service failures, and configuration updates. The system maintains consistency through atomic state transitions and rollback mechanisms.

**State Change Triggers:**

- Network interface up/down events trigger service reconfiguration and routing table updates
- Configuration parameter changes propagate through sysevent bus causing coordinated service updates
- HAL device status changes trigger hardware-specific service adaptations
- External management requests (TR-069, WebUI) initiate controlled configuration transactions

**Context Switching Scenarios:**

- WAN failover scenarios where primary connection failure triggers automatic secondary interface activation
- DHCP lease renewal cycles that may require firewall rule updates and routing changes
- IPv6 address assignment changes that trigger neighbor discovery and routing protocol updates
- Bridge/VLAN reconfiguration events that require coordinated interface state management

### Call Flow

**Initialization Call Flow:**

```mermaid
sequenceDiagram
    participant Init as System Init
    participant Syscfg as Syscfg Service
    participant Sysevent as Sysevent Daemon
    participant Services as Network Services
    participant HAL as HAL Layer

    Init->>Syscfg: Start syscfg service
    Syscfg->>Syscfg: Load configuration from persistent storage
    Syscfg->>Syscfg: Initialize shared memory database
    Syscfg-->>Init: Syscfg ready

    Init->>Sysevent: Start sysevent daemon
    Sysevent->>Sysevent: Create Unix domain socket
    Sysevent->>Sysevent: Initialize event routing tables
    Sysevent-->>Init: Event bus ready

    Init->>Services: Initialize network services
    Services->>Syscfg: Read service configuration
    Services->>Sysevent: Register for events
    Services->>HAL: Initialize hardware interfaces
    HAL-->>Services: Interface status
    Services-->>Init: Services initialized

    Init->>Init: System fully active
```

**Configuration Change Request Processing Call Flow:**

```mermaid
sequenceDiagram
    participant Client as External Client
    participant UTAPI as UTAPI Layer
    participant Syscfg as Syscfg Service
    participant Sysevent as Sysevent Daemon
    participant Service as Network Service
    participant HAL as HAL Layer

    Client->>UTAPI: Configuration change request
    UTAPI->>UTAPI: Validate parameters
    UTAPI->>Syscfg: Update configuration parameter
    Syscfg->>Syscfg: Atomic database update
    Syscfg->>Sysevent: Broadcast config change event
    Sysevent->>Service: Event notification
    Service->>Syscfg: Read updated configuration
    Service->>HAL: Apply hardware changes
    HAL-->>Service: Status confirmation
    Service->>Sysevent: Service update complete
    Sysevent-->>UTAPI: Change propagated
    UTAPI-->>Client: Configuration updated successfully
```

## Internal Modules

Utopia is organized into distinct functional modules that provide specific infrastructure and networking services. Each module operates with clear responsibilities and well-defined interfaces, enabling modular development and platform-specific customization while maintaining system-wide coordination through the core event bus and configuration management systems.

| Module/Class | Description | Key Files |
|-------------|------------|-----------|
| **Sysevent System** | Core inter-process communication daemon providing publish-subscribe event messaging using Unix domain sockets with support for persistent and transient event states | `syseventd_main.c`, `clientsMgr.c`, `triggerMgr.c`, `dataMgr.c` |
| **Syscfg Database** | High-performance configuration persistence service using shared memory with filesystem backing, supporting atomic updates and namespace-based parameter organization | `syscfg_lib.c`, `syscfg.h`, `syscfg/cmd/syscfg.c` |
| **UTAPI Interface** | Unified API layer providing standardized C interfaces and command-line tools for system configuration, network management, and status monitoring | `utapi.c`, `utapi.h`, `utapi_util.h`, `utapi_wlan.h` |
| **DHCP Services** | Comprehensive DHCP server and client management including lease database management, option configuration, and multi-interface support | `service_dhcp.c`, `dhcp_server_functions.c`, `lan_handler.c`, `service_udhcpc.c` |
| **Firewall Management** | Advanced iptables-based firewall service with rule generation, NAT configuration, port triggering, and QoS integration | `firewall.c`, `firewall_interface.c`, `nfq_handler.c` |
| **WAN Service Handler** | WAN interface management supporting multiple connection types (DHCP, PPPoE, static), connection monitoring, and failover capabilities | `service_wan/`, `service_routed.c` |
| **IPv6 Services** | IPv6 address management, routing, and neighbor discovery with support for stateless autoconfiguration and DHCPv6 | `service_ipv6.c`, `service_dhcpv6_client.c` |
| **Multi-Network Management** | VLAN and bridge management service enabling network isolation, service-specific networking, and complex topology support | `service_multinet/`, `service_multinet_swfab.c` |

## Component Interactions

Utopia maintains extensive integration points across the RDK-B middleware stack, providing foundational services that enable coordinated operation of networking, management, and platform services. The component serves as both a service provider and orchestration layer, managing complex interactions between system components while maintaining clean separation of concerns through well-defined interface boundaries.

### Interaction Matrix

| Target Component/Layer | Interaction Purpose | Key APIs/Endpoints |
|------------------------|-------------------|------------------|
| **RDK-B CCSP Components** |
| CcspPandM | Configuration parameter management | `GetParameterValues()`, `SetParameterValues()`, `AddObject()` |
| CcspPsm | Persistent storage manager integration for cross-component data sharing | `PsmSet()`, `PsmGet()`, `PsmGetRecordKeys()` |
| Component Registrar | Service discovery and component lifecycle management | `RegisterComponent()`, `UnregisterComponent()` |
| **Network Management Components** |
| OneWifi | WiFi interface configuration, status monitoring, and event coordination | `wifi-status`, `wifi-restart`, `wlan-configuration` |
| WAN Manager | WAN connection management, failover coordination, and interface binding | `wan-status`, `wan-restart`, `UTAPI_WanConnect()` |
| Ethernet Agent | Ethernet interface management and link status monitoring | `ethernet-status`, `link-up`, `link-down` |
| **System & HAL Layers** |
| Network HAL | Hardware network interface control and status monitoring | `wifi_hal_init()`, `ethernet_hal_getConfig()`, `docsis_hal_*` |
| Linux Network Stack | Network interface configuration, routing, and firewall rule management | `ioctl()`, `netlink_socket()`, `/proc/net/*`, `/sys/class/net/*` |
| Persistent Storage | Configuration data persistence and system defaults management | `/nvram/syscfg.db`, `/etc/utopia/system_defaults` |
| SystemD Services | Process lifecycle management and service coordination | `systemctl start/stop/restart`, service dependency management |


**Main events Published by Utopia:**

| Event Name | Event Topic/Path | Trigger Condition | Subscriber Components |
|------------|-----------------|-------------------|---------------------|
| `system-ready` | `/system/ready` | Complete system initialization finished | All CCSP components, Network Agents |
| `config-changed` | `/config/changed/{parameter}` | Configuration parameter modified via syscfg | Affected service handlers |
| `network-restart` | `/network/restart/{service}` | Network service restart required | Network management components |
| `wan-status` | `/wan/status` | WAN connection state change detected | WAN Manager, Routing services, CCSP components |

### IPC Flow Patterns

**Primary IPC Flow - Configuration Management:**

```mermaid
sequenceDiagram
    participant Client as CCSP Component
    participant UTAPI as UTAPI Layer  
    participant Syscfg as Syscfg Database
    participant Sysevent as Sysevent Bus
    participant Service as Network Service
    participant HAL as HAL Interface

    Client->>UTAPI: SetParameterValue (RBus call)
    UTAPI->>UTAPI: Validate parameter and permissions
    UTAPI->>Syscfg: syscfg_set (shared memory update)
    Syscfg->>Syscfg: Atomic database commit
    Syscfg->>Sysevent: Post config-change event
    Sysevent->>Service: Event notification (Unix socket)
    Service->>Syscfg: syscfg_get (read new configuration)
    Service->>HAL: Apply configuration (HAL API call)
    HAL-->>Service: Status response
    Service->>Sysevent: Post service-ready event
    Sysevent-->>UTAPI: Configuration applied successfully
    UTAPI-->>Client: RBus response (success/failure)
```

**Event Notification Flow:**

```mermaid
sequenceDiagram
    participant HAL as Hardware Layer
    participant Service as Network Service
    participant Sysevent as Sysevent Bus
    participant Subscriber1 as OneWifi
    participant Subscriber2 as WAN Manager
    participant CCSP as CCSP Component

    HAL->>Service: Interface state change interrupt
    Service->>Service: Process hardware event
    Service->>Sysevent: Publish network-status event
    
    Note over Sysevent: Event routing to subscribers
    
    Sysevent->>Subscriber1: Event delivery (Unix socket)
    Sysevent->>Subscriber2: Event delivery (Unix socket)  
    Sysevent->>CCSP: Event notification (RBus signal)
    
    Subscriber1-->>Sysevent: Acknowledgment (if required)
    Subscriber2-->>Sysevent: Acknowledgment (if required)
    CCSP-->>Sysevent: Event processed confirmation
```

## Implementation Details

### Major HAL APIs Integration

Utopia integrates with multiple HAL interface categories to provide comprehensive network device management and monitoring capabilities. The HAL integration layer abstracts platform-specific hardware differences while providing consistent interfaces to upper-layer network services.

**Core HAL APIs:**

| HAL API | Purpose | Implementation File |
|---------|---------|-------------------|
| `wifi_hal_init()` | Initialize WiFi hardware subsystem and establish device communication | `service_dhcp.c`, WiFi service handlers |
| `wifi_hal_getSSIDName()` | Retrieve current SSID configuration for specified radio index | `utapi_wlan.c`, wireless configuration modules |
| `ethernet_hal_getEthWanLinkStatus()` | Check physical link status of WAN ethernet interface | `service_wan/wan_service.c` |
| `docsis_hal_GetDhcpInfo()` | Retrieve DHCP lease information from DOCSIS cable modem | `service_dhcp_server.c` |
| `platform_hal_GetDeviceConfigStatus()` | Query overall device configuration and operational status | `utapi.c`, system status functions |
| `firewall_hal_setFirewallRule()` | Configure hardware firewall rules when hardware acceleration available | `firewall.c`, `firewall_interface.c` |

### Key Implementation Logic

- **Event Bus Architecture**: The sysevent system implements a high-performance Unix domain socket server with multi-client support, event queuing, and trigger-based action execution located in `syseventd_main.c` with client management logic in `clientsMgr.c` and event routing in `triggerMgr.c`. Main implementation in `syseventd_main.c` handles socket server, connection management, and event processing loop. Event routing and subscription management in `triggerMgr.c` provides publish-subscribe functionality with wildcard support. Client connection lifecycle managed in `clientsMgr.c` with authentication and resource tracking. 
  
- **Configuration Database Engine**: Syscfg implements a shared memory-based configuration database optimized for frequent reads and atomic writes, with automatic persistence and namespace support. Primary database engine in `syscfg_lib.c` providing thread-safe shared memory operations. Atomic transaction support with rollback capability for configuration consistency. Namespace isolation enabling multi-tenant configuration management 

- **Network Service Orchestration**: Service handlers coordinate complex networking operations through event-driven state machines that respond to configuration changes and hardware events. DHCP service coordination between server/client modes with lease management. Firewall rule generation from high-level policies to iptables implementation. WAN service state machines for connection establishment and failover management. 

- **Error Handling Strategy**: Comprehensive error detection includes HAL error code mapping, service health monitoring, and automatic recovery mechanisms for transient failures. HAL error code standardization and logging with detailed context information. Service watchdog functionality with automatic restart for failed network services. Configuration validation and rollback on invalid parameter detection. 

- **Logging & Debugging**: Multi-level logging system with category-based filtering, performance metrics, and debugging interfaces for troubleshooting complex network configurations. Structured logging with configurable verbosity levels and category filtering. Performance instrumentation for syscfg operations and event processing latency. Debug hooks enabling runtime inspection of configuration state and event flow. 

### Key Configuration Files

| Configuration File | Purpose | Override Mechanisms |
|--------------------|---------|-------------------|
| `/etc/utopia/system_defaults` | System-wide default configuration template loaded during initialization | Product-specific files, factory reset procedures |
| `/etc/utopia/service.d/service_*/` | Service-specific configuration and script directories | Yocto recipe customization, platform overlays |