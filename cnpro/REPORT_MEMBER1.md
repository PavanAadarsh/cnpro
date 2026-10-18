# UNIVERSITY RESEARCH NETWORK — NETWORK ARCHITECTURE & INFRASTRUCTURE REPORT
**Course:** BACSE203 P Computer Networks Lab  
**Role:** Member 1 — Network Architecture & Baseline Infrastructure  
**Baseline Topology File:** `CN_Baseline_v1.pkt`  
**Git Branch:** `member1-network-architecture`  

---

## 1. Topology Diagram Description
The University Research Network baseline architecture is designed as a centralized, hierarchical single-path campus network structured around a core-in-the-middle model:

- **Core Layer (`CORE-SW` — Cisco Catalyst 3560-24PS):** Functions as the central Layer-3 routing engine and local DHCP server. It hosts Switch Virtual Interfaces (SVIs) for each department and client category (`Vlan10`, `Vlan20`, `Vlan30`, `Vlan40`, `Vlan50`, `Vlan60`, `Vlan70`), performing wire-speed inter-VLAN routing across all campus domains. Its ports `Gi0/1` and `Gi0/2` act as high-speed 802.1Q trunks connecting downlink access switches, while `Fa0/24` is converted into a routed Layer-3 point-to-point link to the edge router. All unused physical access ports (`Fa0/1–23`) are hardcoded into an isolated blackhole VLAN 999 and administratively shut down.
- **Access Layer (`ACCESS-SW-A` & `ACCESS-SW-B` — Cisco Catalyst 2960-24TT):** Provide direct physical edge connectivity to departmental end hosts and servers. 
  - `ACCESS-SW-A` terminates student hosts (`PC-STU1`, `PC-STU2` on VLAN 10), faculty hosts (`PC-FAC1`, `PC-FAC2` on VLAN 20), admin workstations (`PC-ADM1`, `PC-ADM2` on VLAN 40), and the dedicated `POLICY-HOST` (VLAN 40).
  - `ACCESS-SW-B` terminates research workstations (`PC-RES1`, `PC-RES2` on VLAN 30) and the enterprise internal server farm (`SRV-RESEARCH`, `SRV-DB`, `SRV-ADMIN`, `SRV-REMEDIATE` on VLAN 50).
  - Both switches implement Spanning Tree PortFast across all active access ports to provide instantaneous end-device link establishment, with unused ports assigned to VLAN 999 and shut down.
- **Edge Routing & External Gateway Layer (`EDGE-R` — Cisco 2911 Router):** Connects the campus intranet to simulated external networks. Interface `Gi0/0` peers with the Core switch on transit subnet `10.0.0.0/30`, running a static return route (`192.168.0.0/16`) back to `CORE-SW`. Interface `Gi0/1` interfaces with `INTERNET-SRV` over `203.0.113.0/30` and executes Network Address Translation Overload (PAT) using ACL 1, allowing internal private hosts to transparently browse external resources.
- **External Services (`INTERNET-SRV` — Server-PT):** Simulates a public cloud web and DNS authority reachable at public IP `203.0.113.2`, hosting `http://www.example.com`.

```
                  +--------------------------+
                  |       INTERNET-SRV       |
                  |     (203.0.113.2/30)     |
                  +-------------+------------+
                                | (Copper Cross-over)
                                |
                  +-------------+------------+
                  |          EDGE-R          |
                  |      (Cisco 2911)        |
                  | Gi0/0: 10.0.0.2/30       |
                  | Gi0/1: 203.0.113.1/30    |
                  +-------------+------------+
                                | (Copper Straight-Through)
                                |
                  +-------------+------------+
                  |         CORE-SW          |
                  |     (Cisco 3560-24PS)    |
                  |    L3 Routing & DHCP     |
                  |    Fa0/24: 10.0.0.1/30   |
                  +-------+----------+-------+
                          |          |
      (Cross-over Trunk)  |          |  (Cross-over Trunk)
      Gi0/1 <=======> Gi0/1          Gi0/2 <=======> Gi0/1
                          |          |
             +------------+          +------------+
             |                                    |
+------------+-------------+        +-------------+------------+
|       ACCESS-SW-A        |        |       ACCESS-SW-B        |
|    (Cisco 2960-24TT)     |        |    (Cisco 2960-24TT)     |
+------------+-------------+        +-------------+------------+
  |  |  |  |   |  |   |               |  |   |  |  |  |
  |  |  |  |   |  |   +-> POLICY-HOST |  |   |  |  |  +-> SRV-REMEDIATE
  |  |  |  |   |  +-----> PC-ADM2     |  |   |  |  +----> SRV-ADMIN
  |  |  |  |   +--------> PC-ADM1     |  |   |  +-------> SRV-DB
  |  |  |  +------------> PC-FAC2     |  |   +----------> SRV-RESEARCH
  |  |  +---------------> PC-FAC1     |  +--------------> PC-RES2
  |  +------------------> PC-STU2     +-----------------> PC-RES1
  +---------------------> PC-STU1
```

---

## 2. VLAN Table
All VLAN subnets use a standard `/24` prefix (Subnet Mask: `255.255.255.0`). VTP is configured in `transparent` mode on all three switches.

| VLAN ID | VLAN Name | Subnet Network | Default Gateway (CORE-SW SVI) | Static IP Range | Dynamic DHCP Leased Range | Functional Role |
|---|---|---|---|---|---|---|
| **10** | STUDENTS | 192.168.10.0/24 | 192.168.10.1 | .2 – .99 | .100 – .254 | Student body client workstations |
| **20** | FACULTY | 192.168.20.0/24 | 192.168.20.1 | .2 – .99 | .100 – .254 | Faculty and instructional devices |
| **30** | RESEARCH | 192.168.30.0/24 | 192.168.30.1 | .2 – .99 | .100 – .254 | Research lab endpoints |
| **40** | ADMIN | 192.168.40.0/24 | 192.168.40.1 | .2 – .99 | .100 – .254 | Campus administration, switch management, Policy Host |
| **50** | SERVERS | 192.168.50.0/24 | 192.168.50.1 | .2 – .254 | None (All Static) | Core intranet infrastructure servers |
| **60** | RESTRICTED | 192.168.60.0/24 | 192.168.60.1 | .2 – .99 | .100 – .254 | Remediation zone for non-compliant devices |
| **70** | QUARANTINE | 192.168.70.0/24 | 192.168.70.1 | .2 – .99 | .100 – .254 | Isolation zone for compromised devices |
| **999** | BLACKHOLE | None | None | None | None | Native 802.1Q VLAN & unused disabled switchports |

---

## 3. IP Addressing Table
All hosts configure DNS Server `203.0.113.2`.

| Device Name | Interface | IP Address | Subnet Mask | Default Gateway | Addressing Type |
|---|---|---|---|---|---|
| **CORE-SW** | Vlan 10 | 192.168.10.1 | 255.255.255.0 | N/A (Local SVI) | Static |
| **CORE-SW** | Vlan 20 | 192.168.20.1 | 255.255.255.0 | N/A (Local SVI) | Static |
| **CORE-SW** | Vlan 30 | 192.168.30.1 | 255.255.255.0 | N/A (Local SVI) | Static |
| **CORE-SW** | Vlan 40 | 192.168.40.1 | 255.255.255.0 | N/A (Local SVI) | Static |
| **CORE-SW** | Vlan 50 | 192.168.50.1 | 255.255.255.0 | N/A (Local SVI) | Static |
| **CORE-SW** | Vlan 60 | 192.168.60.1 | 255.255.255.0 | N/A (Local SVI) | Static |
| **CORE-SW** | Vlan 70 | 192.168.70.1 | 255.255.255.0 | N/A (Local SVI) | Static |
| **CORE-SW** | Fa0/24 | 10.0.0.1 | 255.255.255.252 | N/A (Point-to-Point) | Static |
| **ACCESS-SW-A** | Vlan 40 | 192.168.40.21 | 255.255.255.0 | 192.168.40.1 | Static |
| **ACCESS-SW-B** | Vlan 40 | 192.168.40.22 | 255.255.255.0 | 192.168.40.1 | Static |
| **EDGE-R** | Gi0/0 | 10.0.0.2 | 255.255.255.252 | N/A (Point-to-Point) | Static |
| **EDGE-R** | Gi0/1 | 203.0.113.1 | 255.255.255.252 | N/A (Public Subnet) | Static |
| **INTERNET-SRV** | Fa0 | 203.0.113.2 | 255.255.255.252 | 203.0.113.1 | Static |
| **SRV-RESEARCH** | Fa0 | 192.168.50.10 | 255.255.255.0 | 192.168.50.1 | Static |
| **SRV-DB** | Fa0 | 192.168.50.11 | 255.255.255.0 | 192.168.50.1 | Static |
| **SRV-ADMIN** | Fa0 | 192.168.50.12 | 255.255.255.0 | 192.168.50.1 | Static |
| **SRV-REMEDIATE**| Fa0 | 192.168.50.13 | 255.255.255.0 | 192.168.50.1 | Static |
| **POLICY-HOST** | Fa0 | 192.168.40.50 | 255.255.255.0 | 192.168.40.1 | Static |
| **PC-STU1** | Fa0 | 192.168.10.100+ | 255.255.255.0 | 192.168.10.1 | Dynamic (DHCP) |
| **PC-STU2** | Fa0 | 192.168.10.100+ | 255.255.255.0 | 192.168.10.1 | Dynamic (DHCP) |
| **PC-FAC1** | Fa0 | 192.168.20.100+ | 255.255.255.0 | 192.168.20.1 | Dynamic (DHCP) |
| **PC-FAC2** | Fa0 | 192.168.20.100+ | 255.255.255.0 | 192.168.20.1 | Dynamic (DHCP) |
| **PC-ADM1** | Fa0 | 192.168.40.100+ | 255.255.255.0 | 192.168.40.1 | Dynamic (DHCP) |
| **PC-ADM2** | Fa0 | 192.168.40.100+ | 255.255.255.0 | 192.168.40.1 | Dynamic (DHCP) |
| **PC-RES1** | Fa0 | 192.168.30.100+ | 255.255.255.0 | 192.168.30.1 | Dynamic (DHCP) |
| **PC-RES2** | Fa0 | 192.168.30.100+ | 255.255.255.0 | 192.168.30.1 | Dynamic (DHCP) |

---

## 4. Cabling & Port Allocation Table

| Source Device & Port | Destination Device & Port | Media / Cable Type | Port Mode | VLAN ID / Subnet | Operational State |
|---|---|---|---|---|---|
| **CORE-SW Gi0/1** | ACCESS-SW-A Gi0/1 | Copper Cross-over | Trunk (802.1Q) | Native 999; Allowed 10,20,30,40,50,60,70 | Up / Up |
| **CORE-SW Gi0/2** | ACCESS-SW-B Gi0/1 | Copper Cross-over | Trunk (802.1Q) | Native 999; Allowed 10,20,30,40,50,60,70 | Up / Up |
| **CORE-SW Fa0/24** | EDGE-R Gi0/0 | Copper Straight-Through | Routed (No Switchport) | 10.0.0.0/30 Point-to-Point | Up / Up |
| **EDGE-R Gi0/1** | INTERNET-SRV Fa0 | Copper Cross-over | Routed Interface | 203.0.113.0/30 External Subnet | Up / Up |
| **ACCESS-SW-A Fa0/1** | PC-STU1 Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 10 (STUDENTS) | Up / Up |
| **ACCESS-SW-A Fa0/2** | PC-STU2 Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 10 (STUDENTS) | Up / Up |
| **ACCESS-SW-A Fa0/3** | PC-FAC1 Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 20 (FACULTY) | Up / Up |
| **ACCESS-SW-A Fa0/4** | PC-FAC2 Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 20 (FACULTY) | Up / Up |
| **ACCESS-SW-A Fa0/5** | PC-ADM1 Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 40 (ADMIN) | Up / Up |
| **ACCESS-SW-A Fa0/6** | PC-ADM2 Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 40 (ADMIN) | Up / Up |
| **ACCESS-SW-A Fa0/7** | POLICY-HOST Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 40 (ADMIN) | Up / Up |
| **ACCESS-SW-A Fa0/8–24, Gi0/2** | Unconnected | None | Access | VLAN 999 (BLACKHOLE) | Administratively Down |
| **ACCESS-SW-B Fa0/1** | PC-RES1 Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 30 (RESEARCH) | Up / Up |
| **ACCESS-SW-B Fa0/2** | PC-RES2 Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 30 (RESEARCH) | Up / Up |
| **ACCESS-SW-B Fa0/3** | SRV-RESEARCH Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 50 (SERVERS) | Up / Up |
| **ACCESS-SW-B Fa0/4** | SRV-DB Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 50 (SERVERS) | Up / Up |
| **ACCESS-SW-B Fa0/5** | SRV-ADMIN Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 50 (SERVERS) | Up / Up |
| **ACCESS-SW-B Fa0/6** | SRV-REMEDIATE Fa0 | Copper Straight-Through | Access (PortFast) | VLAN 50 (SERVERS) | Up / Up |
| **ACCESS-SW-B Fa0/7–24, Gi0/2** | Unconnected | None | Access | VLAN 999 (BLACKHOLE) | Administratively Down |
| **CORE-SW Fa0/1–23** | Unconnected | None | Access | VLAN 999 (BLACKHOLE) | Administratively Down |

---

## 5. Configuration Excerpts

### A. Core Switch (`CORE-SW`) Routing, SVIs, & DHCP Pools
```text
ip routing
!
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
 no shutdown
!
interface Vlan20
 ip address 192.168.20.1 255.255.255.0
 no shutdown
!
interface Vlan30
 ip address 192.168.30.1 255.255.255.0
 no shutdown
!
interface Vlan40
 ip address 192.168.40.1 255.255.255.0
 no shutdown
!
interface Vlan50
 ip address 192.168.50.1 255.255.255.0
 no shutdown
!
interface Vlan60
 ip address 192.168.60.1 255.255.255.0
 no shutdown
!
interface Vlan70
 ip address 192.168.70.1 255.255.255.0
 no shutdown
!
interface FastEthernet0/24
 description ROUTED-TO-EDGE-R
 no switchport
 ip address 10.0.0.1 255.255.255.252
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 10.0.0.2
!
ip dhcp excluded-address 192.168.10.1 192.168.10.99
ip dhcp excluded-address 192.168.20.1 192.168.20.99
ip dhcp excluded-address 192.168.30.1 192.168.30.99
ip dhcp excluded-address 192.168.40.1 192.168.40.99
ip dhcp excluded-address 192.168.60.1 192.168.60.99
ip dhcp excluded-address 192.168.70.1 192.168.70.99
!
ip dhcp pool DHCP-STU
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1
 dns-server 203.0.113.2
ip dhcp pool DHCP-FAC
 network 192.168.20.0 255.255.255.0
 default-router 192.168.20.1
 dns-server 203.0.113.2
ip dhcp pool DHCP-RES
 network 192.168.30.0 255.255.255.0
 default-router 192.168.30.1
 dns-server 203.0.113.2
ip dhcp pool DHCP-ADM
 network 192.168.40.0 255.255.255.0
 default-router 192.168.40.1
 dns-server 203.0.113.2
ip dhcp pool DHCP-RSTR
 network 192.168.60.0 255.255.255.0
 default-router 192.168.60.1
 dns-server 203.0.113.2
ip dhcp pool DHCP-QUAR
 network 192.168.70.0 255.255.255.0
 default-router 192.168.70.1
 dns-server 203.0.113.2
```

### B. Access Switches (`ACCESS-SW-A` & `B`) 802.1Q Trunks & Management
```text
! ACCESS-SW-A: Vlan40 = 192.168.40.21 | ACCESS-SW-B: Vlan40 = 192.168.40.22
interface GigabitEthernet0/1
 description TRUNK-TO-CORE-SW
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30,40,50,60,70
!
interface Vlan40
 ip address 192.168.40.21 255.255.255.0
!
ip default-gateway 192.168.40.1
ip ssh version 2
```

### C. Edge Router (`EDGE-R`) Static Routing & NAT Overload
```text
interface GigabitEthernet0/0
 description TO-CORE-SW
 ip address 10.0.0.2 255.255.255.252
 ip nat inside
!
interface GigabitEthernet0/1
 description TO-INTERNET-SRV
 ip address 203.0.113.1 255.255.255.252
 ip nat outside
!
ip route 192.168.0.0 255.255.0.0 10.0.0.1
access-list 1 permit 192.168.0.0 0.0.255.255
ip nat inside source list 1 interface GigabitEthernet0/1 overload
```

---

## 6. Test Matrix with Results (Tests T1–T15)

| ID | Verification Test | Command / Method | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| **T1** | VLAN Database & Access Port Check | `show vlan brief` on switches | VLANs 10–70 and 999 present; ports mapped per 4.5 | All 8 VLANs active; unused ports in 999 | **PASS** |
| **T2** | 802.1Q Trunk Links Verification | `show interfaces trunk` on CORE-SW | Gi0/1 and Gi0/2 trunking; Native 999; Allowed 10,20,30,40,50,60,70 | Encapsulation 802.1q; trunks active | **PASS** |
| **T3** | Core Switch SVI & Link States | `show ip interface brief` on CORE-SW | Vlan10–70 up/up (.1 IPs); Fa0/24 up/up (10.0.0.1) | All SVIs and routed links up/up | **PASS** |
| **T4** | Core Switch Routing Table | `show ip route` on CORE-SW | 7 connected VLAN subnets + 10.0.0.0/30; default route to 10.0.0.2 | Routing active; static default installed | **PASS** |
| **T5** | Edge Router Routing Table | `show ip route` on EDGE-R | Connected /30 subnets; static 192.168.0.0/16 to 10.0.0.1 | Return route to Core switch operational | **PASS** |
| **T6** | Core Switch DHCP Binding Pool | `show ip dhcp binding` on CORE-SW | 8 client leases (.100+ range in subnets 10, 20, 30, 40) | 8 distinct host leases active | **PASS** |
| **T7** | Default Gateway Ping | `ping <VLAN-gateway-IP>` from each PC | 100% ICMP echo reply from local SVI | All 8 PCs reach their respective gateway | **PASS** |
| **T8** | Inter-VLAN & Server Routing | `ping` across subnets and to 192.168.50.x | Unrestricted Layer-3 connectivity (baseline permits all) | All PCs communicate across subnets/servers| **PASS** |
| **T9** | Simulated Internet & DNS | Ping `203.0.113.2` & `www.example.com`; Browser HTTP | Name resolves; HTTP web page renders | Web page loaded successfully | **PASS** |
| **T10**| NAT Overload (PAT) Sessions | `show ip nat translations` on EDGE-R | Inside local IP translated to 203.0.113.1 | Dynamic translation entries confirmed | **PASS** |
| **T11**| Secure Remote Management SSH | `ssh -l admin 192.168.40.x` from POLICY-HOST | Password prompt `<LAB_PASSWORD>`; CLI shell access | SSH v2 session established on all switches | **PASS** |
| **T12**| Dynamic Containment: VLAN 60 | Switchport Fa0/2 $\rightarrow$ VLAN 60; `ipconfig /renew` | Leases 192.168.60.100+; pings 192.168.60.1 | Isolation into VLAN 60 verified | **PASS** |
| **T13**| Dynamic Containment: VLAN 70 | Switchport Fa0/2 $\rightarrow$ VLAN 70; `ipconfig /renew` | Leases 192.168.70.100+; pings 192.168.70.1 | Quarantine into VLAN 70 verified | **PASS** |
| **T14**| Port Reversion to Normal | Switchport Fa0/2 $\rightarrow$ VLAN 10; `ipconfig /renew` | Reacquires 192.168.10.100+; pings 192.168.10.1 | Restored to normal student network | **PASS** |
| **T15**| NVRAM Configuration Persistence | `show startup-config` on all 4 devices | Running-config matches NVRAM startup config | Configurations persisted on all devices | **PASS** |

---

## 7. Screenshots List (Report Evidence Catalog)
The following visual artifacts have been captured as experimental evidence:

1. **Topology Overview:** Complete Packet Tracer canvas showing all labeled routers, switches, servers, and clients with green link indicators (`CN_Baseline_v1.pkt`).
2. **Switch Trunking:** `CORE-SW` CLI showing `show interfaces trunk` verifying trunks `Gi0/1` and `Gi0/2` with native VLAN 999.
3. **Core Interface Status:** `CORE-SW` CLI showing `show ip interface brief` with SVIs 10, 20, 30, 40, 50, 60, 70 in `up/up` state.
4. **Core Routing Table:** `CORE-SW` CLI showing `show ip route` with 8 connected subnets and the default gateway route `0.0.0.0/0 via 10.0.0.2`.
5. **Edge Routing Table:** `EDGE-R` CLI showing `show ip route` with the static return path `192.168.0.0/16 via 10.0.0.1`.
6. **DHCP Bindings:** `CORE-SW` CLI showing `show ip dhcp binding` with 8 leased IP addresses in the `.100+` ranges.
7. **PC DHCP Verification:** `PC-STU1` IP Configuration window displaying automatic lease of IP, mask, gateway (`192.168.10.1`), and DNS (`203.0.113.2`).
8. **Gateway Ping:** `PC-STU1` command prompt displaying successful ping to its default gateway `192.168.10.1`.
9. **Inter-VLAN Communication:** `PC-STU1` command prompt showing successful ping to `192.168.50.10` (`SRV-RESEARCH`) across the Core routing engine.
10. **Internet & DNS Resolution:** `PC-STU1` Web Browser rendering `http://www.example.com` resolved through `INTERNET-SRV`.
11. **NAT Translations:** `EDGE-R` CLI showing `show ip nat translations` translating private campus requests to public IP `203.0.113.1`.
12. **SSH Administrative Access:** `POLICY-HOST` terminal displaying successful SSH authentication into `CORE-SW` (`192.168.40.1`), `ACCESS-SW-A` (`192.168.40.21`), and `ACCESS-SW-B` (`192.168.40.22`).
13. **Dynamic VLAN 60 Containment:** `PC-STU2` command prompt showing `ipconfig /renew` leasing `192.168.60.100+` and pinging `192.168.60.1`.
14. **Dynamic VLAN 70 Quarantine:** `PC-STU2` command prompt showing `ipconfig /renew` leasing `192.168.70.100+` and pinging `192.168.70.1`.
15. **Device NVRAM Persistence:** Console logs showing `[OK]` output from `copy running-config startup-config` across all four infrastructure devices.

---

## 8. Why Restriction is Enforced by VLAN Placement Rather Than by ARP
Restricting or quarantining an endpoint by reassigning its physical switchport to an isolated VLAN (such as VLAN 60 or VLAN 70) is fundamentally superior to attempting restriction by manipulating the Address Resolution Protocol (ARP). ARP is an unauthenticated Layer-2 resolution protocol that resides entirely within the operating system network stack of individual hosts; modifying ARP mappings or relying on ARP poisoning/cache alteration requires invasive host-level tampering, is easily circumvented or corrected by a sophisticated user, and fails to stop raw Layer-2 Ethernet frame transmission or broadcast flooding. In contrast, 802.1Q VLAN assignment enforces physical and logical isolation at the hardware switching ASIC level: the switch completely separates broadcast domains, preventing an endpoint in the quarantined VLAN from ever transmitting or receiving frames to/from unauthorized subnets at Layer 2. Any inter-subnet communication must then traverse the Core Layer-3 switch, where centralized Access Control Lists (ACLs) can deterministically inspect, log, restrict, or deny traffic regardless of host OS behavior, while allowing standard OS protocols like DHCP and standard ARP resolution to continue functioning normally. ARP itself is left completely untouched: it continues to run as normal operating-system behavior inside whichever broadcast domain the device is currently placed in, and the design never modifies or filters ARP; restriction comes solely from VLAN placement and, later, ACLs at the Core Layer-3 switch.
