# Phase 9: Security Verification Test Matrix (Security ACLs & Dynamic Containment)

**Course:** BACSE203 P Computer Networks Lab  
**Role:** Member 2 — Security Policy, Access Control Matrix & Traffic Filtering  
**Document:** `docs/09_security_verification_matrix.md`  
**Evaluation Reference:** Cross-referenced with Member 4's `monitoring/scenarios.json` and Member 1's Baseline Infrastructure  

---

## 1. Security Verification Test Suite (Tests S1 – S20)

| Test ID | Test Description | Source Device / VLAN | Destination / Target | Command / Protocol | Expected Outcome | Verification Criteria | Status |
|---|---|---|---|---|---|---|---|
| **S1** | **DHCP Preservation (Normal State)** | `PC-STU1` (VLAN 10) | `CORE-SW` SVI 10 | `ipconfig /renew` (UDP 67/68) | **PERMIT** | Successfully obtains lease `192.168.10.100+`, mask, gateway, DNS | **PASS** |
| **S2** | **DHCP Preservation (Restricted State)** | `PC-STU2` (VLAN 60) | `CORE-SW` SVI 60 | `ipconfig /renew` (UDP 67/68) | **PERMIT** | Successfully obtains lease `192.168.60.100+` in remediation subnet | **PASS** |
| **S3** | **DHCP Preservation (Quarantine State)** | `PC-STU2` (VLAN 70) | `CORE-SW` SVI 70 | `ipconfig /renew` (UDP 67/68) | **PERMIT** | Successfully obtains lease `192.168.70.100+` in quarantine subnet | **PASS** |
| **S4** | **Policy Host Switch Management SSH** | `POLICY-HOST` (VLAN 40) | `CORE-SW` (`192.168.40.1`), `ACCESS-SW-A` (.21), `ACCESS-SW-B` (.22) | `ssh -l admin 192.168.40.x` (TCP 22) | **PERMIT** | Password prompt opens; successful SSH shell session | **PASS** |
| **S5** | **Student Unauthorized Switch SSH Denial**| `PC-STU1` (VLAN 10) | `192.168.40.1`, `192.168.40.21`, `192.168.40.22` | `ssh -l admin 192.168.40.x` (TCP 22) | **DENY** | Connection refused / Destination Host Unreachable | **PASS** |
| **S6** | **Simulated Internet DNS Resolution** | `PC-STU1` (VLAN 10) | `INTERNET-SRV` (`203.0.113.2`) | `nslookup www.example.com` (UDP 53) | **PERMIT** | Resolves address `203.0.113.2` through EDGE-R NAT | **PASS** |
| **S7** | **Simulated Internet Web Browsing** | `PC-STU1` (VLAN 10) | `INTERNET-SRV` (`203.0.113.2`) | Browser `http://www.example.com` (TCP 80) | **PERMIT** | Web page renders successfully via NAT Overload PAT | **PASS** |
| **S8** | **Authorized Research Access (Scenario: authorized)** | `PC-RES1` (VLAN 30) | `SRV-RESEARCH` (`192.168.50.10`) | Browser `http://192.168.50.10` (TCP 80) | **PERMIT** | Research web portal renders with HTTP 200 OK | **PASS** |
| **S9** | **Authorized Research Database Access** | `PC-RES1` (VLAN 30) | `SRV-DB` (`192.168.50.11`) | Command Prompt `ftp 192.168.50.11` (TCP 21) | **PERMIT** | FTP authentication prompt displayed | **PASS** |
| **S10**| **Student Denied Admin Server (Scenario: protected_access)** | `PC-STU2` (VLAN 10) | `SRV-ADMIN` (`192.168.50.12`) | Browser `http://192.168.50.12` (TCP 80) | **DENY** | Request timed out; packet dropped by `ACL-VLAN10-STUDENTS-IN` | **PASS** |
| **S11**| **Student Denied Research Database Access**| `PC-STU1` (VLAN 10) | `SRV-DB` (`192.168.50.11`) | Command Prompt `ftp 192.168.50.11` (TCP 21) | **DENY** | FTP connection fails / connection timed out | **PASS** |
| **S12**| **Lateral Inter-VLAN Isolation** | `PC-STU1` (VLAN 10) | `PC-ADM1` (`192.168.40.100`) | `ping 192.168.40.100` (ICMP) | **DENY** | Packets dropped at Core ingress; no lateral movement | **PASS** |
| **S13**| **Dynamic Containment Trigger (Scenario: violations)** | `PC-STU2` (VLAN 10) | `SRV-ADMIN` (`192.168.50.12`) | Repeated TCP 80 access attempts | **TRIGGER** | Member 3 Policy Engine detects repeated violations and reassigns Fa0/2 | **PASS** |
| **S14**| **Restricted State Remediation Access (Scenario: recovery)**| `PC-STU2` (VLAN 60) | `SRV-REMEDIATE` (`192.168.50.13`) | Browser `http://192.168.50.13` (TCP 80) | **PERMIT** | Remediation portal renders; user can download compliance patch | **PASS** |
| **S15**| **Restricted State External Isolation** | `PC-STU2` (VLAN 60) | `INTERNET-SRV` (`203.0.113.2`) | Browser `http://www.example.com` (TCP 80) | **DENY** | Blocked; infected/violating device cannot contact internet | **PASS** |
| **S16**| **Restricted State Server Isolation** | `PC-STU2` (VLAN 60) | `SRV-RESEARCH` (`192.168.50.10`) | Browser `http://192.168.50.10` (TCP 80) | **DENY** | Blocked by `ACL-VLAN60-RESTRICTED-IN`; research data protected | **PASS** |
| **S17**| **Quarantine State Total Isolation** | `PC-STU2` (VLAN 70) | All Servers & Internet | Any HTTP/FTP/ICMP connection | **DENY** | Total drop by `ACL-VLAN70-QUARANTINE-IN`; zero routed traffic allowed | **PASS** |
| **S18**| **Collateral Traffic Non-Interference (Scenario: legitimate_transition)** | `PC-RES1` (VLAN 30) | `SRV-RESEARCH` (`192.168.50.10`) | Continuous HTTP requests during STU2 quarantine | **PERMIT** | 100% legitimate research session continuity; zero collateral packet loss | **PASS** |
| **S19**| **Post-Remediation Restoration (Scenario: recovery)** | `PC-STU2` (Restored to VLAN 10) | Gateway & Internet | `ipconfig /renew` & Browser `http://www.example.com` | **PERMIT** | Leases `192.168.10.x` again; normal internet web access fully restored | **PASS** |
| **S20**| **Performance Benchmarking (Scenario: performance)** | `PC-RES1` (VLAN 30) | `SRV-RESEARCH` (`192.168.50.10`) | 20 ICMP Echo Probes (`ping 192.168.50.10`) | **PERMIT** | 0% packet loss, RTT < 2 ms across Core Layer-3 switching fabric | **PASS** |

---

## 2. Alignment with Member 4 Evaluation Framework

The tests above map directly to the scenario identifiers defined in Member 4's `monitoring/scenarios.json`:

```json
{
  "authorized": "Test S8 (PC-RES1 -> SRV-RESEARCH HTTP 80: PERMIT)",
  "protected_access": "Test S10 (PC-STU2 -> SRV-ADMIN HTTP 80: DENY)",
  "violations": "Test S13 (PC-STU2 repeated unauthorized access -> trigger containment)",
  "legitimate_transition": "Test S18 (PC-RES1 unaffected during PC-STU2 quarantine)",
  "recovery": "Tests S14 & S19 (VLAN 60 remediation access -> restoration to VLAN 10)",
  "performance": "Test S20 (PC-RES1 -> SRV-RESEARCH 20 ICMP probes: 0% loss, < 2 ms)"
}
```
