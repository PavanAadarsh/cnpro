# Comprehensive Access Control Matrix & Security Filtering Policy

**Course:** BACSE203 P Computer Networks Lab  
**Project:** University Research Network with Adaptive Access Control and Dynamic Segmentation  
**Role:** Member 2 — Security Policy, Access Control Matrix & Traffic Filtering  
**Target Infrastructure:** Cisco Catalyst 3560-24PS (`CORE-SW`) Layer-3 Switch Virtual Interfaces (SVIs)  
**Document:** `docs/02_access_control_matrix.md`  

---

## 1. Executive Summary & Design Philosophy

The security model of the University Research Network enforces **Zero-Trust Network Access (ZTNA) principles** and **least-privilege access control** across all academic and administrative domains. While Member 1 established an unrestricted inter-VLAN routing baseline across 7 functional subnets, Member 2 implements strict deterministic traffic boundaries at Layer 3 and Layer 4.

### Inbound SVI Filtering Architecture
All Access Control Lists (ACLs) are authored as **Cisco IOS Extended Named ACLs** and bound **INBOUND (`ip access-group <ACL> in`)** on the respective Switch Virtual Interfaces (SVIs) of `CORE-SW`:
- **Early Dropping at Ingress:** By filtering incoming packets on the SVI interface as soon as they arrive from access switch trunk links (`Gi0/1` and `Gi0/2`), unauthorized packets are discarded *before* consuming Layer-3 route-lookup cycles or transit switching fabric bandwidth.
- **Spoofing Prevention:** Ingress rules on `Vlan10` strictly validate that the source IP matches `192.168.10.0/24` (or `any` for raw DHCP discovery), stopping cross-subnet address spoofing at the core boundary.
- **Preservation of Untouched External Infrastructure:** EDGE-R `access-list 1` is preserved strictly for NAT overload PAT. All security filtering is localized to `CORE-SW`.

---

## 2. Global Role-to-Service Access Control Matrix

The matrix below defines permitted and denied communication channels across all campus network entities:

| Source Entity / VLAN | Destination Entity | Target IP / Subnet | Protocol & Port | State | Action | Academic & Security Rationale |
|---|---|---|---|---|---|---|
| **STUDENTS (VLAN 10)** | CORE-SW SVI 10 | 192.168.10.1 | UDP 67 / 68 (DHCP) | Normal | **PERMIT** | Mandatory host IP leasing and network configuration |
| **STUDENTS (VLAN 10)** | Local Gateway SVI | 192.168.10.1 | ICMP (Echo Request) | Normal | **PERMIT** | Network diagnostic reachability |
| **STUDENTS (VLAN 10)** | INTERNET-SRV | 203.0.113.2 | UDP/TCP 53 (DNS) | Normal | **PERMIT** | Name resolution for academic web domains |
| **STUDENTS (VLAN 10)** | INTERNET-SRV | 203.0.113.2 | TCP 80 / 443 (HTTP/S) | Normal | **PERMIT** | Public internet browsing via EDGE-R NAT PAT |
| **STUDENTS (VLAN 10)** | SRV-REMEDIATE | 192.168.50.13 | TCP 80 (HTTP) | Normal | **PERMIT** | Access to campus software updates and policy guidelines |
| **STUDENTS (VLAN 10)** | SRV-RESEARCH | 192.168.50.10 | TCP 80 (HTTP) | Normal | **PERMIT** | Public reading access to university research papers |
| **STUDENTS (VLAN 10)** | SRV-ADMIN | 192.168.50.12 | TCP 80 / 443 (HTTP/S) | Normal | **DENY** | **Scenario `protected_access`**: Students forbidden from admin server |
| **STUDENTS (VLAN 10)** | SRV-DB | 192.168.50.11 | TCP 20 / 21 (FTP) | Normal | **DENY** | Confidential research database isolation |
| **STUDENTS (VLAN 10)** | Switch Management | 192.168.40.1, .21, .22 | TCP 22 (SSH) | Normal | **DENY** | Infrastructure switch hardening against student unauthorized access |
| **STUDENTS (VLAN 10)** | ADMIN (VLAN 40) | 192.168.40.0/24 | Any IP | Normal | **DENY** | Inter-VLAN isolation of administrative personnel endpoints |
| **STUDENTS (VLAN 10)** | FACULTY (VLAN 20) | 192.168.20.0/24 | Any IP | Normal | **DENY** | Inter-VLAN isolation of instructional staff endpoints |
| **STUDENTS (VLAN 10)** | RESEARCH (VLAN 30) | 192.168.30.0/24 | Any IP | Normal | **DENY** | Inter-VLAN isolation of research laboratory devices |
|---|---|---|---|---|---|---|
| **FACULTY (VLAN 20)** | CORE-SW SVI 20 | 192.168.20.1 | UDP 67 / 68 (DHCP) | Normal | **PERMIT** | Dynamic IP leasing |
| **FACULTY (VLAN 20)** | Local Gateway SVI | 192.168.20.1 | ICMP | Normal | **PERMIT** | Diagnostic ping |
| **FACULTY (VLAN 20)** | INTERNET-SRV | 203.0.113.2 | UDP/TCP 53, TCP 80/443 | Normal | **PERMIT** | Full external internet browsing and DNS |
| **FACULTY (VLAN 20)** | SRV-RESEARCH | 192.168.50.10 | TCP 80 / 443 (HTTP/S) | Normal | **PERMIT** | Instructional research collaboration and document review |
| **FACULTY (VLAN 20)** | SRV-REMEDIATE | 192.168.50.13 | TCP 80 / UDP 53 | Normal | **PERMIT** | Campus software library and internal DNS |
| **FACULTY (VLAN 20)** | SRV-ADMIN | 192.168.50.12 | Any | Normal | **DENY** | Administrative infrastructure separation |
| **FACULTY (VLAN 20)** | Switch Management | 192.168.40.0/24 | TCP 22 (SSH) | Normal | **DENY** | Switch management reserved for Policy Host & Admin |
|---|---|---|---|---|---|---|
| **RESEARCH (VLAN 30)** | CORE-SW SVI 30 | 192.168.30.1 | UDP 67 / 68 (DHCP) | Normal | **PERMIT** | Dynamic IP configuration |
| **RESEARCH (VLAN 30)** | SRV-RESEARCH | 192.168.50.10 | TCP 80 / 443 | Normal | **PERMIT** | **Scenario `authorized`**: Core research application read/write |
| **RESEARCH (VLAN 30)** | SRV-DB | 192.168.50.11 | TCP 20 / 21 (FTP) | Normal | **PERMIT** | Large dataset transfer and repository synchronization |
| **RESEARCH (VLAN 30)** | INTERNET-SRV | 203.0.113.2 | UDP 53, TCP 80 / 443 | Normal | **PERMIT** | External journal access and academic web connectivity |
| **RESEARCH (VLAN 30)** | SRV-RESEARCH | 192.168.50.10 | ICMP | Normal | **PERMIT** | **Scenario `performance`**: Baseline latency and loss benchmarks |
| **RESEARCH (VLAN 30)** | SRV-ADMIN | 192.168.50.12 | Any | Normal | **DENY** | Separation of academic research from campus administrative systems |
| **RESEARCH (VLAN 30)** | Switch Management | 192.168.40.0/24 | TCP 22 (SSH) | Normal | **DENY** | Infrastructure switch protection |
|---|---|---|---|---|---|---|
| **ADMIN (VLAN 40)** | POLICY-HOST (.50) | 192.168.40.1, .21, .22 | TCP 22 (SSH) | Normal | **PERMIT** | **Mandatory Contract**: Switch configuration & containment automation |
| **ADMIN (VLAN 40)** | SRV-ADMIN | 192.168.50.12 | TCP 80 / 443 | Normal | **PERMIT** | Campus administrative portal management |
| **ADMIN (VLAN 40)** | All Servers (VLAN 50)| 192.168.50.0/24 | Any IP | Normal | **PERMIT** | Administrative maintenance and audits |
| **ADMIN (VLAN 40)** | INTERNET-SRV | 203.0.113.2 | All Internet Ports | Normal | **PERMIT** | External administrative management |
|---|---|---|---|---|---|---|
| **RESTRICTED (VLAN 60)**| CORE-SW SVI 60 | 192.168.60.1 | UDP 67 / 68 (DHCP) | Restricted| **PERMIT** | **Scenario `recovery`**: Re-leasing IP in remediation subnet |
| **RESTRICTED (VLAN 60)**| Local Gateway SVI | 192.168.60.1 | ICMP (Echo Request) | Restricted| **PERMIT** | Host local stack verification |
| **RESTRICTED (VLAN 60)**| SRV-REMEDIATE | 192.168.50.13 | UDP/TCP 53 (DNS) | Restricted| **PERMIT** | Remediation portal name lookup |
| **RESTRICTED (VLAN 60)**| SRV-REMEDIATE | 192.168.50.13 | TCP 80 (HTTP) | Restricted| **PERMIT** | **Scenario `recovery`**: Access remediation portal for patch verification |
| **RESTRICTED (VLAN 60)**| SRV-ADMIN | 192.168.50.12 | Any | Restricted| **DENY** | Complete denial of protected administrative server |
| **RESTRICTED (VLAN 60)**| SRV-RESEARCH | 192.168.50.10 | Any | Restricted| **DENY** | Complete denial of research assets |
| **RESTRICTED (VLAN 60)**| SRV-DB | 192.168.50.11 | Any | Restricted| **DENY** | Complete denial of research database |
| **RESTRICTED (VLAN 60)**| INTERNET-SRV | 203.0.113.2 | Any | Restricted| **DENY** | Isolated from internet to prevent external command & control (C2) |
| **RESTRICTED (VLAN 60)**| Any Campus VLAN | 192.168.0.0/16 | Any | Restricted| **DENY** | Containment: blocked from laterally spreading to students/faculty/admin |
|---|---|---|---|---|---|---|
| **QUARANTINE (VLAN 70)**| CORE-SW SVI 70 | 192.168.70.1 | UDP 67 / 68 (DHCP) | Quarantine| **PERMIT** | IP leasing inside quarantine broadcast domain |
| **QUARANTINE (VLAN 70)**| Local Gateway SVI | 192.168.70.1 | ICMP (Echo Request) | Quarantine| **PERMIT** | Local link state confirmation |
| **QUARANTINE (VLAN 70)**| Any Internal Server | 192.168.50.0/24 | Any | Quarantine| **DENY** | **Total Lockdown**: Blocked from all servers |
| **QUARANTINE (VLAN 70)**| INTERNET-SRV | 203.0.113.2 | Any | Quarantine| **DENY** | Total internet block |
| **QUARANTINE (VLAN 70)**| Any Campus VLAN | 192.168.0.0/16 | Any | Quarantine| **DENY** | Total lateral isolation |

---

## 3. Dynamic Containment State Lifecycle Transitions

The security policy explicitly models the three dynamic containment states managed by Member 3's Policy Engine and measured by Member 4's evaluation framework:

```text
                  +----------------------------------------------+
                  |                 NORMAL STATE                 |
                  |  Endpoint on Fa0/1 or Fa0/2 in VLAN 10       |
                  |  Permitted: Internet, DNS, Research Web      |
                  |  Denied: SRV-ADMIN, SRV-DB, Switch SSH       |
                  +----------------------+-----------------------+
                                         |
                                         | Violation Threshold Exceeded
                                         | (Attempted SRV-ADMIN Access)
                                         v
                  +----------------------------------------------+
                  |               RESTRICTED STATE               |
                  |  Port reassigned to VLAN 60 (192.168.60.x)   |
                  |  Permitted: DHCP, SRV-REMEDIATE (HTTP/DNS)   |
                  |  Denied: ALL other servers, subnets, Internet|
                  +----------------------+-----------------------+
                                         |
                                         | Critical Security Breach /
                                         | Sustained Violation
                                         v
                  +----------------------------------------------+
                  |               QUARANTINE STATE               |
                  |  Port reassigned to VLAN 70 (192.168.70.x)   |
                  |  Permitted: DHCP only                        |
                  |  Denied: Total lockdown (0 routed access)    |
                  +----------------------+-----------------------+
                                         |
                                         | Policy Engine Recovery Condition
                                         | (Remediation Validated)
                                         v
                  +----------------------------------------------+
                  |               RECOVERY TO NORMAL             |
                  |  Port restored to VLAN 10 (192.168.10.x)     |
                  |  ipconfig /renew issued                      |
                  |  Full normal baseline access restored        |
                  +----------------------------------------------+
```

---

## 4. Port and Protocol Specification Reference

| Service Name | Transport Protocol | Port Number(s) | Destination Host | Purpose in Topology |
|---|---|---|---|---|
| **DHCP** | UDP | 67 (Server), 68 (Client) | `255.255.255.255` / Local SVI | Dynamic IP allocation for all client devices |
| **DNS** | UDP / TCP | 53 | `203.0.113.2`, `192.168.50.13` | Domain resolution for internet & internal remediation |
| **HTTP** | TCP | 80 | `203.0.113.2`, `192.168.50.10`, `192.168.50.12`, `192.168.50.13` | Web portal access across cloud, research, admin, remediation |
| **HTTPS** | TCP | 443 | `203.0.113.2`, `192.168.50.10`, `192.168.50.12` | Encrypted web access |
| **FTP** | TCP | 21 (Control), 20 (Data) | `192.168.50.11` | Scientific database file transfers |
| **SSH** | TCP | 22 | `192.168.40.1`, `192.168.40.21`, `192.168.40.22` | Secure remote management from `POLICY-HOST` (`192.168.40.50`) |
| **ICMP** | ICMP | Types 8 (Echo), 0 (Reply), 3, 11 | Gateway SVIs & Permitted Hosts | Network layer latency and loss benchmarking |
