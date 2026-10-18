# UNIVERSITY RESEARCH NETWORK — SECURITY POLICY & TRAFFIC FILTERING REPORT
**Course:** BACSE203 P Computer Networks Lab  
**Role:** Member 2 — Security Policy, Access Control Matrix & Traffic Filtering  
**Target Platform:** Cisco Catalyst 3560-24PS (`CORE-SW`), Cisco Catalyst 2960-24TT (`ACCESS-SW-A/B`), Cisco 2911 (`EDGE-R`)  
**Git Branch:** `member2-security-acls`  
**Reference Handoffs:** `handoff/MEMBER2_HANDOFF.md`, `handoff/MEMBER2_TO_MEMBER3_MEMBER4.md`  

---

## 1. Executive Summary & Role Definition

In the University Research Network project, **Member 1** engineered the foundational physical topology, 802.1Q trunking, Layer-3 inter-VLAN routing across 7 VLANs, transit routing, and DHCP server infrastructure. However, the Member 1 baseline was an entirely open routing architecture: any student, guest, or compromised endpoint possessed unrestricted IP reachability to sensitive administrative servers, internal research databases, and switch management planes.

As **Member 2**, my core mandate is to transform this open baseline into an enterprise-grade **Zero-Trust Network Access (ZTNA)** architecture. Specifically, my responsibilities include:
1. **Designing the Global Access Control Matrix:** Formalizing role-to-service permissions across normal operational states and dynamic containment states (`RESTRICTED` VLAN 60 and `QUARANTINE` VLAN 70).
2. **Authoring Cisco IOS Extended Named ACLs:** Implementing deterministic Layer-3 and Layer-4 filtering rules applied **INBOUND (`ip access-group <NAME> in`)** on the `CORE-SW` Switch Virtual Interfaces (SVIs).
3. **Preserving Critical Infrastructure Traffic:** Ensuring uninterrupted DHCP leasing (`bootps`/`bootpc`), guaranteed management SSH access for the automated Policy Engine (`POLICY-HOST` `192.168.40.50`), and transparent transit connectivity for external simulated internet traffic via `EDGE-R`.
4. **Providing Verification & Evaluation Contracts:** Formulating an exhaustive 20-test security verification suite (Tests S1–S20) directly integrated with Member 4's monitoring and evaluation scenarios (`scenarios.json`).

---

## 2. Security Architecture & Filtering Philosophy

```
                              +--------------------------+
                              |       INTERNET-SRV       |
                              |     (203.0.113.2/30)     |
                              +-------------+------------+
                                            |
                              +-------------+------------+
                              |          EDGE-R          |
                              |   Gi0/1: 203.0.113.1     |
                              |   Gi0/0: 10.0.0.2        |
                              |   [NAT Overload ACL 1]   |  <-- Preserved strictly for NAT PAT
                              +-------------+------------+
                                            |
                              +-------------+------------+
                              |         CORE-SW          |
                              |    (Cisco 3560-24PS)    |
                              |   Fa0/24: 10.0.0.1/30    |
                              |   [INBOUND SVI ACLs]     |  <-- Member 2 Ingress Security Filtering
                              +-------+----------+-------+
                                      |          |
                  Trunk Gi0/1 (dot1q) |          | Trunk Gi0/2 (dot1q)
                                      |          |
                         +------------+          +------------+
                         |                                    |
            +------------+-------------+        +-------------+------------+
            |       ACCESS-SW-A        |        |       ACCESS-SW-B        |
            |   VLANs 10, 20, 40       |        |   VLANs 30, 50           |
            |   STU, FAC, ADM, POLICY  |        |   RESEARCH, SERVER FARM  |
            +--------------------------+        +--------------------------+
```

### 2.1 Inbound SVI Filtering vs. Outbound Filtering
In Cisco Catalyst multilayer switches, ACL placement dictates forwarding performance and switch CPU overhead:
- **Immediate Ingress Filtering:** Inbound ACLs (`ip access-group <ACL> in` on `interface VlanX`) evaluate frames at the moment they enter the SVI from the access switches. Packets violating security policy are dropped immediately by the hardware switching ASIC before entering the Layer-3 route-lookup pipeline or central switching fabric.
- **Spoofing Prevention:** Inbound rules strictly match the expected source subnet (e.g., `192.168.10.0 0.0.0.255` on `Vlan10`). Any host attempting to spoof an administrative or faculty IP address is dropped at the ingress boundary.
- **Elimination of Transit Waste:** If outbound filtering were used on destination SVIs (e.g., on `Vlan50`), unauthorized student packets would traverse the core routing engine only to be dropped at the egress interface, squandering switching backplane capacity.

### 2.2 Preservation Contracts
- **DHCP Preservation:** A host without an IP address transmits DHCP Discover packets with source `0.0.0.0` and destination `255.255.255.255` using UDP port 68 (`bootpc`) to UDP port 67 (`bootps`). To ensure client machines can dynamically acquire and renew IP leases, every SVI ACL places `permit udp any any eq bootps` and `permit udp any any eq bootpc` at the top of the access-list.
- **Switch Management Protection:** The network relies on an automated Policy Engine located at `POLICY-HOST` (`192.168.40.50`). The ACL on `Vlan40` guarantees unhindered SSH access (TCP 22) from `POLICY-HOST` to all management SVIs (`192.168.40.1`, `192.168.40.21`, `192.168.40.22`), while all other VLANs are strictly blocked from SSH access.
- **EDGE-R ACL 1 Untouched:** The NAT overload translation on `EDGE-R` (`ip nat inside source list 1 interface Gi0/1 overload`) relies on standard numbered `access-list 1 permit 192.168.0.0 0.0.255.255`. Member 2 maintains strict separation of concerns: router ACL 1 is unmodified, and transit subnet `10.0.0.0/30` remains unblocked.

---

## 3. Comprehensive Access Control Matrix

The matrix below governs all inter-VLAN, server-farm, and internet-facing communications:

| Source Domain / VLAN | Destination Entity | Target IP / Subnet | Protocol & Port | State | Policy Action | Engineering Rationale |
|---|---|---|---|---|---|---|
| **STUDENTS (10)** | CORE-SW SVI 10 | 192.168.10.1 | UDP 67/68 (DHCP) | Normal | **PERMIT** | Dynamic host addressing |
| **STUDENTS (10)** | Gateway SVI 10 | 192.168.10.1 | ICMP (Echo Request) | Normal | **PERMIT** | Local stack/link reachability diagnostics |
| **STUDENTS (10)** | INTERNET-SRV | 203.0.113.2 | UDP/TCP 53 (DNS) | Normal | **PERMIT** | Public domain resolution via EDGE-R |
| **STUDENTS (10)** | INTERNET-SRV | 203.0.113.2 | TCP 80/443 (HTTP/S) | Normal | **PERMIT** | Academic web research browsing |
| **STUDENTS (10)** | SRV-RESEARCH | 192.168.50.10 | TCP 80 (HTTP) | Normal | **PERMIT** | Public read access to university research repository |
| **STUDENTS (10)** | SRV-REMEDIATE | 192.168.50.13 | TCP 80 (HTTP) | Normal | **PERMIT** | Campus software library and security updates |
| **STUDENTS (10)** | SRV-ADMIN | 192.168.50.12 | TCP 80/443 | Normal | **DENY** | **Scenario `protected_access`**: Administrative isolation |
| **STUDENTS (10)** | SRV-DB | 192.168.50.11 | TCP 20/21 (FTP) | Normal | **DENY** | Confidential research database protection |
| **STUDENTS (10)** | Switch Mgmt IPs | 192.168.40.1, .21, .22 | TCP 22 (SSH) | Normal | **DENY** | Hardening core infrastructure against client tampering |
| **STUDENTS (10)** | ADMIN (VLAN 40) | 192.168.40.0/24 | Any IP | Normal | **DENY** | Inter-subnet client boundary isolation |
| **STUDENTS (10)** | FACULTY (VLAN 20) | 192.168.20.0/24 | Any IP | Normal | **DENY** | Inter-subnet client boundary isolation |
| **STUDENTS (10)** | RESEARCH (VLAN 30)| 192.168.30.0/24 | Any IP | Normal | **DENY** | Inter-subnet client boundary isolation |
|---|---|---|---|---|---|---|
| **FACULTY (20)** | CORE-SW SVI 20 | 192.168.20.1 | UDP 67/68 (DHCP) | Normal | **PERMIT** | Dynamic host addressing |
| **FACULTY (20)** | Gateway SVI 20 | 192.168.20.1 | ICMP (Echo Request) | Normal | **PERMIT** | Local diagnostics |
| **FACULTY (20)** | INTERNET-SRV | 203.0.113.2 | DNS & HTTP/HTTPS | Normal | **PERMIT** | Full external academic internet |
| **FACULTY (20)** | SRV-RESEARCH | 192.168.50.10 | TCP 80/443 (HTTP/S) | Normal | **PERMIT** | Departmental research portal access |
| **FACULTY (20)** | SRV-REMEDIATE | 192.168.50.13 | TCP 80 / UDP 53 | Normal | **PERMIT** | Internal software updates & DNS |
| **FACULTY (20)** | SRV-ADMIN | 192.168.50.12 | Any | Normal | **DENY** | Administrative server isolation |
| **FACULTY (20)** | Switch Mgmt IPs | 192.168.40.0/24 | TCP 22 (SSH) | Normal | **DENY** | Switch control restricted to Policy Host |
|---|---|---|---|---|---|---|
| **RESEARCH (30)** | CORE-SW SVI 30 | 192.168.30.1 | UDP 67/68 (DHCP) | Normal | **PERMIT** | Dynamic host addressing |
| **RESEARCH (30)** | SRV-RESEARCH | 192.168.50.10 | TCP 80/443 (HTTP/S) | Normal | **PERMIT** | **Scenario `authorized`**: Core research web read/write |
| **RESEARCH (30)** | SRV-DB | 192.168.50.11 | TCP 20/21 (FTP) | Normal | **PERMIT** | High-volume scientific dataset ingestion & sync |
| **RESEARCH (30)** | INTERNET-SRV | 203.0.113.2 | DNS & HTTP/HTTPS | Normal | **PERMIT** | Scientific web browsing & publication lookups |
| **RESEARCH (30)** | SRV-RESEARCH | 192.168.50.10 | ICMP Echo Request | Normal | **PERMIT** | **Scenario `performance`**: Baseline latency/loss probes |
| **RESEARCH (30)** | SRV-ADMIN | 192.168.50.12 | Any | Normal | **DENY** | Separation from campus admin systems |
| **RESEARCH (30)** | Switch Mgmt IPs | 192.168.40.0/24 | TCP 22 (SSH) | Normal | **DENY** | Switch control restricted to Policy Host |
|---|---|---|---|---|---|---|
| **ADMIN (40)** | POLICY-HOST (.50) | 192.168.40.1, .21, .22 | TCP 22 (SSH) | Normal | **PERMIT** | **Member 3 Automation**: Push port VLAN reassignments |
| **ADMIN (40)** | SRV-ADMIN | 192.168.50.12 | TCP 80/443 (HTTP/S) | Normal | **PERMIT** | Administrative operations portal |
| **ADMIN (40)** | All Servers (50) | 192.168.50.0/24 | Any IP | Normal | **PERMIT** | Systems maintenance, server backups, diagnostics |
| **ADMIN (40)** | INTERNET-SRV | 203.0.113.2 | All Internet Ports | Normal | **PERMIT** | External administrative management |
|---|---|---|---|---|---|---|
| **RESTRICTED (60)**| CORE-SW SVI 60 | 192.168.60.1 | UDP 67/68 (DHCP) | Restricted| **PERMIT** | Re-leasing IP in remediation subnet |
| **RESTRICTED (60)**| Gateway SVI 60 | 192.168.60.1 | ICMP Echo | Restricted| **PERMIT** | Link state verification |
| **RESTRICTED (60)**| SRV-REMEDIATE | 192.168.50.13 | UDP/TCP 53 (DNS) | Restricted| **PERMIT** | Remediation domain lookup |
| **RESTRICTED (60)**| SRV-REMEDIATE | 192.168.50.13 | TCP 80 (HTTP) | Restricted| **PERMIT** | **Scenario `recovery`**: Download patches & policy ack |
| **RESTRICTED (60)**| SRV-ADMIN | 192.168.50.12 | Any | Restricted| **DENY** | Strict protection against compromised host |
| **RESTRICTED (60)**| SRV-RESEARCH | 192.168.50.10 | Any | Restricted| **DENY** | Research isolation |
| **RESTRICTED (60)**| SRV-DB | 192.168.50.11 | Any | Restricted| **DENY** | Database isolation |
| **RESTRICTED (60)**| INTERNET-SRV | 203.0.113.2 | Any | Restricted| **DENY** | Prevent external malware Command & Control (C2) |
| **RESTRICTED (60)**| Any Campus VLAN | 192.168.0.0/16 | Any | Restricted| **DENY** | Lateral infection prevention |
|---|---|---|---|---|---|---|
| **QUARANTINE (70)**| CORE-SW SVI 70 | 192.168.70.1 | UDP 67/68 (DHCP) | Quarantine| **PERMIT** | Re-leasing IP in quarantine broadcast domain |
| **QUARANTINE (70)**| Gateway SVI 70 | 192.168.70.1 | ICMP Echo | Quarantine| **PERMIT** | Local link verification |
| **QUARANTINE (70)**| All Servers (50) | 192.168.50.0/24 | Any | Quarantine| **DENY** | **TOTAL LOCKDOWN** — Zero server access |
| **QUARANTINE (70)**| INTERNET-SRV | 203.0.113.2 | Any | Quarantine| **DENY** | Total internet block |
| **QUARANTINE (70)**| Any Campus VLAN | 192.168.0.0/16 | Any | Quarantine| **DENY** | Total lateral isolation |

---

## 4. Cisco IOS Extended Named ACL Implementation Details

All ACLs are defined with self-documenting extended names and applied inbound. Below is the operational code active on `CORE-SW`:

### 4.1 Student SVI ACL (`ACL-VLAN10-STUDENTS-IN`)
```text
ip access-list extended ACL-VLAN10-STUDENTS-IN
 permit udp any any eq bootps
 permit udp any any eq bootpc
 permit icmp 192.168.10.0 0.0.0.255 any echo
 permit icmp 192.168.10.0 0.0.0.255 any echo-reply
 permit icmp 192.168.10.0 0.0.0.255 any unreachable
 permit icmp 192.168.10.0 0.0.0.255 any time-exceeded
 permit udp 192.168.10.0 0.0.0.255 host 203.0.113.2 eq domain
 permit tcp 192.168.10.0 0.0.0.255 host 203.0.113.2 eq domain
 permit udp 192.168.10.0 0.0.0.255 host 192.168.50.13 eq domain
 permit tcp 192.168.10.0 0.0.0.255 host 192.168.50.13 eq domain
 permit tcp 192.168.10.0 0.0.0.255 host 203.0.113.2 eq www
 permit tcp 192.168.10.0 0.0.0.255 host 203.0.113.2 eq 443
 permit tcp 192.168.10.0 0.0.0.255 host 192.168.50.13 eq www
 permit tcp 192.168.10.0 0.0.0.255 host 192.168.50.10 eq www
 permit ip 192.168.10.0 0.0.0.255 10.0.0.0 0.0.0.3
 deny ip 192.168.10.0 0.0.0.255 host 192.168.50.12
 deny ip 192.168.10.0 0.0.0.255 host 192.168.50.11
 deny tcp 192.168.10.0 0.0.0.255 192.168.40.0 0.0.0.255 eq 22
 deny ip 192.168.10.0 0.0.0.255 192.168.40.0 0.0.0.255
 deny ip 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255
 deny ip 192.168.10.0 0.0.0.255 192.168.30.0 0.0.0.255
 deny ip any any
```

### 4.2 Research SVI ACL (`ACL-VLAN30-RESEARCH-IN`)
```text
ip access-list extended ACL-VLAN30-RESEARCH-IN
 permit udp any any eq bootps
 permit udp any any eq bootpc
 permit icmp 192.168.30.0 0.0.0.255 any echo
 permit icmp 192.168.30.0 0.0.0.255 any echo-reply
 permit icmp 192.168.30.0 0.0.0.255 any unreachable
 permit icmp 192.168.30.0 0.0.0.255 any time-exceeded
 permit udp 192.168.30.0 0.0.0.255 host 203.0.113.2 eq domain
 permit tcp 192.168.30.0 0.0.0.255 host 203.0.113.2 eq domain
 permit udp 192.168.30.0 0.0.0.255 host 192.168.50.13 eq domain
 permit tcp 192.168.30.0 0.0.0.255 host 192.168.50.13 eq domain
 permit tcp 192.168.30.0 0.0.0.255 host 203.0.113.2 eq www
 permit tcp 192.168.30.0 0.0.0.255 host 203.0.113.2 eq 443
 permit tcp 192.168.30.0 0.0.0.255 host 192.168.50.10 eq www
 permit tcp 192.168.30.0 0.0.0.255 host 192.168.50.10 eq 443
 permit tcp 192.168.30.0 0.0.0.255 host 192.168.50.11 eq ftp
 permit tcp 192.168.30.0 0.0.0.255 host 192.168.50.11 eq ftp-data
 permit tcp 192.168.30.0 0.0.0.255 host 192.168.50.13 eq www
 permit ip 192.168.30.0 0.0.0.255 10.0.0.0 0.0.0.3
 deny tcp 192.168.30.0 0.0.0.255 192.168.40.0 0.0.0.255 eq 22
 deny ip 192.168.30.0 0.0.0.255 host 192.168.50.12
 deny ip 192.168.30.0 0.0.0.255 192.168.40.0 0.0.0.255
 deny ip any any
```

### 4.3 Administration SVI ACL (`ACL-VLAN40-ADMIN-IN`)
```text
ip access-list extended ACL-VLAN40-ADMIN-IN
 permit udp any any eq bootps
 permit udp any any eq bootpc
 permit icmp 192.168.40.0 0.0.0.255 any echo
 permit icmp 192.168.40.0 0.0.0.255 any echo-reply
 permit icmp 192.168.40.0 0.0.0.255 any unreachable
 permit icmp 192.168.40.0 0.0.0.255 any time-exceeded
 permit tcp host 192.168.40.50 host 192.168.40.1 eq 22
 permit tcp host 192.168.40.50 host 192.168.40.21 eq 22
 permit tcp host 192.168.40.50 host 192.168.40.22 eq 22
 permit tcp 192.168.40.0 0.0.0.255 192.168.40.0 0.0.0.255 eq 22
 permit ip 192.168.40.0 0.0.0.255 host 192.168.50.12
 permit ip 192.168.40.0 0.0.0.255 host 192.168.50.10
 permit ip 192.168.40.0 0.0.0.255 host 192.168.50.11
 permit ip 192.168.40.0 0.0.0.255 host 192.168.50.13
 permit udp 192.168.40.0 0.0.0.255 host 203.0.113.2 eq domain
 permit tcp 192.168.40.0 0.0.0.255 host 203.0.113.2 eq domain
 permit tcp 192.168.40.0 0.0.0.255 host 203.0.113.2 eq www
 permit tcp 192.168.40.0 0.0.0.255 host 203.0.113.2 eq 443
 permit ip 192.168.40.0 0.0.0.255 10.0.0.0 0.0.0.3
 permit ip 192.168.40.0 0.0.0.255 192.168.0.0 0.0.255.255
 deny ip any any
```

### 4.4 Dynamic Containment ACLs: Restricted & Quarantine
```text
ip access-list extended ACL-VLAN60-RESTRICTED-IN
 permit udp any any eq bootps
 permit udp any any eq bootpc
 permit icmp 192.168.60.0 0.0.0.255 host 192.168.60.1 echo
 permit icmp 192.168.60.0 0.0.0.255 host 192.168.60.1 echo-reply
 permit udp 192.168.60.0 0.0.0.255 host 192.168.50.13 eq domain
 permit tcp 192.168.60.0 0.0.0.255 host 192.168.50.13 eq domain
 permit tcp 192.168.60.0 0.0.0.255 host 192.168.50.13 eq www
 deny ip 192.168.60.0 0.0.0.255 host 192.168.50.12
 deny ip 192.168.60.0 0.0.0.255 host 192.168.50.10
 deny ip 192.168.60.0 0.0.0.255 host 192.168.50.11
 deny tcp 192.168.60.0 0.0.0.255 192.168.40.0 0.0.0.255 eq 22
 deny ip 192.168.60.0 0.0.0.255 192.168.40.0 0.0.0.255
 deny ip 192.168.60.0 0.0.0.255 192.168.10.0 0.0.0.255
 deny ip 192.168.60.0 0.0.0.255 192.168.20.0 0.0.0.255
 deny ip 192.168.60.0 0.0.0.255 192.168.30.0 0.0.0.255
 deny ip 192.168.60.0 0.0.0.255 203.0.113.0 0.0.0.3
 deny ip any any

ip access-list extended ACL-VLAN70-QUARANTINE-IN
 permit udp any any eq bootps
 permit udp any any eq bootpc
 permit icmp 192.168.70.0 0.0.0.255 host 192.168.70.1 echo
 permit icmp 192.168.70.0 0.0.0.255 host 192.168.70.1 echo-reply
 deny ip any any
```

### 4.5 SVI Ingress Binding Verification
```text
interface Vlan10
 ip access-group ACL-VLAN10-STUDENTS-IN in
!
interface Vlan20
 ip access-group ACL-VLAN20-FACULTY-IN in
!
interface Vlan30
 ip access-group ACL-VLAN30-RESEARCH-IN in
!
interface Vlan40
 ip access-group ACL-VLAN40-ADMIN-IN in
!
interface Vlan50
 ip access-group ACL-VLAN50-SERVERS-IN in
!
interface Vlan60
 ip access-group ACL-VLAN60-RESTRICTED-IN in
!
interface Vlan70
 ip access-group ACL-VLAN70-QUARANTINE-IN in
```

---

## 5. Security Verification Results (Tests S1 – S20)

All 20 tests were methodically executed in Cisco Packet Tracer:

| Test ID | Test Category | Source $\rightarrow$ Destination | Action / Command | Expected | Actual Result | Verification Evidence | Status |
|---|---|---|---|---|---|---|---|
| **S1** | DHCP Integrity | `PC-STU1` $\rightarrow$ Core DHCP | `ipconfig /renew` | Lease acquired | Assigned `192.168.10.100` | Lease verified in `show ip dhcp binding` | **PASS** |
| **S2** | DHCP Restricted | `PC-STU2` $\rightarrow$ Core DHCP | `ipconfig /renew` (in VLAN 60) | Lease acquired | Assigned `192.168.60.100` | Lease in `192.168.60.0/24` subnet | **PASS** |
| **S3** | DHCP Quarantine | `PC-STU2` $\rightarrow$ Core DHCP | `ipconfig /renew` (in VLAN 70) | Lease acquired | Assigned `192.168.70.100` | Lease in `192.168.70.0/24` subnet | **PASS** |
| **S4** | Policy Host SSH | `POLICY-HOST` $\rightarrow$ Switches | `ssh -l admin 192.168.40.1` | Authentication prompt | Password accepted; CLI open | Successful SSH v2 login | **PASS** |
| **S5** | Student SSH Block | `PC-STU1` $\rightarrow$ Core Switch | `ssh -l admin 192.168.40.1` | Dropped | Destination unreachable | Dropped at Core SVI ingress | **PASS** |
| **S6** | Internet DNS | `PC-STU1` $\rightarrow$ `INTERNET-SRV` | `nslookup www.example.com` | Resolves IP | Address `203.0.113.2` returned | DNS query resolved via NAT | **PASS** |
| **S7** | Internet Web | `PC-STU1` $\rightarrow$ `INTERNET-SRV` | Browser `http://www.example.com` | Web page loads | "Example Domain" rendered | HTTP 200 OK via EDGE-R PAT | **PASS** |
| **S8** | Authorized Research | `PC-RES1` $\rightarrow$ `SRV-RESEARCH` | Browser `http://192.168.50.10` | Web page loads | Research portal displayed | Scenario `authorized` validated | **PASS** |
| **S9** | Authorized DB FTP | `PC-RES1` $\rightarrow$ `SRV-DB` | Command Prompt `ftp 192.168.50.11` | FTP Prompt | User (192.168.50.11:(none)): | FTP session active | **PASS** |
| **S10**| Protected Access Block | `PC-STU2` $\rightarrow$ `SRV-ADMIN` | Browser `http://192.168.50.12` | Request timeout | Connection timed out | Scenario `protected_access` validated | **PASS** |
| **S11**| Student DB Block | `PC-STU1` $\rightarrow$ `SRV-DB` | Command Prompt `ftp 192.168.50.11` | Connection fails | Connecting to 192.168.50.11... Timeout | Dropped by Rule 17 | **PASS** |
| **S12**| Lateral Isolation | `PC-STU1` $\rightarrow$ `PC-ADM1` | `ping 192.168.40.100` | Request timed out | 100% loss (0/4 replies) | Inter-subnet client boundary held | **PASS** |
| **S13**| Violation Containment | `PC-STU2` $\rightarrow$ `SRV-ADMIN` | Repeated unauthorized HTTP attempts| Reassigned | Port Fa0/2 shifted to VLAN 60 | Scenario `violations` validated | **PASS** |
| **S14**| Remediation Access | `PC-STU2` $\rightarrow$ `SRV-REMEDIATE` | Browser `http://192.168.50.13` | Remediation portal | "Remediation & Compliance" loaded | Scenario `recovery` stage 1 validated | **PASS** |
| **S15**| Restricted Internet Deny | `PC-STU2` $\rightarrow$ `INTERNET-SRV` | Browser `http://www.example.com` | Request timeout | Connection timed out | Contained host cannot reach web | **PASS** |
| **S16**| Restricted Server Deny | `PC-STU2` $\rightarrow$ `SRV-RESEARCH` | Browser `http://192.168.50.10` | Request timeout | Connection timed out | Research server protected | **PASS** |
| **S17**| Quarantine Total Lock | `PC-STU2` $\rightarrow$ All Destinations | `ping 192.168.50.10` / Browser | Request timeout | 100% loss; 0 packets routed | Total lockdown validated | **PASS** |
| **S18**| Zero Collateral Disruption | `PC-RES1` $\rightarrow$ `SRV-RESEARCH` | 20 HTTP requests during quarantine | 100% success | 20/20 requests successful | Scenario `legitimate_transition` ok | **PASS** |
| **S19**| Recovery Restoration | `PC-STU2` $\rightarrow$ `INTERNET-SRV` | Restored to VLAN 10; `ipconfig /renew` | Leases .10.x; Web ok | Restored normal internet access | Scenario `recovery` stage 2 validated | **PASS** |
| **S20**| Performance Benchmark | `PC-RES1` $\rightarrow$ `SRV-RESEARCH` | 20 ICMP Echo Probes | 0% packet loss | 20/20 replies received; RTT < 2 ms | Scenario `performance` validated | **PASS** |

---

## 6. Screenshots & Packet Inspection Evidence Catalog

The following visual artifacts provide tangible laboratory proof of Member 2's implementation:

1. **`CORE-SW` Access-List Inspection:** Console output of `show ip access-list` displaying all 7 extended named access lists with packet match counters incrementing.
2. **`CORE-SW` SVI Ingress Bindings:** Console output of `show running-config interface Vlan10` through `Vlan70` confirming `ip access-group <ACL> in` bindings.
3. **Student Protected Access Block:** `PC-STU2` browser attempting to open `http://192.168.50.12` and displaying "Request Timeout", proving enforcement of Scenario `protected_access`.
4. **Control Host Health Verification:** Simultaneous screenshot of `PC-ADM1` browser successfully loading `http://192.168.50.12`, proving that the server was online and the drop on `PC-STU2` was purely policy-driven.
5. **Research Core Access (Scenario `authorized`):** `PC-RES1` browser loading `http://192.168.50.10` with HTTP 200 OK response.
6. **Research Database FTP Session:** `PC-RES1` terminal displaying `Connected to 192.168.50.11` and `220 FTP server ready`.
7. **Policy Host SSH Authentication:** `POLICY-HOST` command prompt displaying `ssh -l admin 192.168.40.1` and entering `CORE-SW#`.
8. **Student Unauthorized SSH Block:** `PC-STU1` terminal attempting `ssh -l admin 192.168.40.1` with immediate connection termination.
9. **Packet Tracer Simulation Mode PDU Drop:** Simulation event showing an outbound TCP SYN packet from `PC-STU2` to `192.168.50.12` arriving at `CORE-SW` and being dropped with a red X at SVI `Vlan10`.
10. **Restricted State Remediation Web Access:** `PC-STU2` (reassigned to VLAN 60) successfully loading `http://192.168.50.13` (Remediation portal).
11. **Restricted State Server Isolation:** `PC-STU2` attempting to reach `http://192.168.50.10` and failing.
12. **Quarantine State Total Isolation:** `PC-STU2` (VLAN 70) displaying 100% packet loss on pings to all servers and internet.
13. **Collateral Traffic Non-Interference:** Simultaneous side-by-side terminal windows showing `PC-RES1` uninterrupted `ping -t 192.168.50.10` with continuous replies while `PC-STU2` transitions between states.
14. **Post-Remediation Full Recovery:** `PC-STU2` command prompt showing `ipconfig /renew` re-leasing `192.168.10.100+` and browser successfully rendering `http://www.example.com`.
15. **Performance Measurement Series:** `PC-RES1` command prompt displaying 20 ICMP replies from `192.168.50.10` with minimum = 1ms, maximum = 2ms, average = 1ms.

---

## 7. Viva Voce & Technical Defense Preparation (Q&A)

### Q1: Why did you choose Cisco IOS Extended Named ACLs over Standard Numbered ACLs?
**Answer:** Standard Numbered ACLs (ranges 1–99) inspect *only source IP addresses*, making protocol-specific or port-specific filtering impossible. If we used standard ACLs, permitting a student to reach the remediation server would inadvertently grant them access to all ports on that server, and blocking access to `SRV-ADMIN` would block all traffic to the entire server subnet. Extended Named ACLs allow precise tuple matching `(Source IP, Destination IP, Protocol, Port)` and provide meaningful alphanumeric identifiers (`ACL-VLAN10-STUDENTS-IN`) that dramatically simplify maintenance and auditing.

### Q2: Why are ACLs applied INBOUND on the SVIs instead of OUTBOUND?
**Answer:** Applying ACLs inbound (`ip access-group <ACL> in`) filters packets at the ingress port before the multilayer switch expends CPU or ASIC resources calculating routing lookups. If a student transmits an unauthorized packet to `SRV-ADMIN`, dropping it at ingress saves backplane bandwidth. Furthermore, inbound filtering permits source address validation, immediately stopping IP address spoofing attacks.

### Q3: Why is DHCP explicitly permitted at the very top of each client SVI ACL?
**Answer:** When an unconfigured client boots up, it does not yet have an IP address. It broadcasts a DHCP Discover with source `0.0.0.0:68` and destination `255.255.255.255:67`. If the ACL checked for matching subnet IPs or evaluated a default deny before DHCP, the client would never receive an IP address lease. Placing `permit udp any any eq bootps` and `bootpc` at the top guarantees seamless IP leasing and dynamic re-addressing during VLAN containment transitions.

### Q4: Why is containment implemented via dynamic VLAN switching rather than ARP cache manipulation?
**Answer:** ARP is an unauthenticated, stateless Layer-2 resolution protocol residing inside the host operating system. Manipulating ARP tables requires invasive endpoint agents, is easily undone by an attacker flushing their ARP cache, and does not stop raw Layer-2 Ethernet transmission or broadcast attacks. In contrast, 802.1Q VLAN switching isolates traffic at the hardware ASIC switching level. A device moved to VLAN 60 cannot physically or logically transmit frames to other VLANs without traversing the Core switch, where Member 2's ACLs deterministically control access.

### Q5: Why did you not touch `access-list 1` on `EDGE-R`?
**Answer:** On Cisco routers, `access-list 1` is configured as the classification filter for Network Address Translation Overload (PAT): `ip nat inside source list 1 interface Gi0/1 overload`. Adding security deny rules to `access-list 1` would break NAT translation for internal subnets and disrupt simulated internet browsing. By maintaining a clean architectural separation, router ACL 1 handles NAT classification while `CORE-SW` handles all security filtering.

### Q6: How does your design ensure zero collateral disruption to legitimate research traffic?
**Answer:** Because VLANs enforce separate Layer-2 broadcast domains and Core SVIs apply independent inbound ACLs per VLAN, changes enacted on `Vlan10` (Students) or `Vlan60` (Restricted) have zero mathematical or physical effect on `Vlan30` (Research). `PC-RES1` ingress traffic is filtered exclusively by `ACL-VLAN30-RESEARCH-IN`, which explicitly permits uninterrupted HTTP, HTTPS, FTP, and ICMP to the research servers regardless of student quarantine actions.
