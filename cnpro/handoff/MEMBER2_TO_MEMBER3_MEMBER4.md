# Handoff Package from Member 2 to Member 3 & Member 4

**Course:** BACSE203 P Computer Networks Lab  
**Author:** Member 2 — Security Policy, Access Control Matrix & Traffic Filtering  
**Recipients:**  
- **Member 3:** Policy Engine & Dynamic Containment  
- **Member 4:** Monitoring, Evaluation & Performance Analysis  
**Date:** October 2026  
**Document:** `handoff/MEMBER2_TO_MEMBER3_MEMBER4.md`  

---

## 1. Overview of Delivered Security Controls

Member 2 has delivered a complete Layer-3/Layer-4 security filtering framework applied inbound to all Switch Virtual Interfaces (SVIs) on `CORE-SW` (Cisco Catalyst 3560). This framework upgrades the baseline open routing infrastructure into a strictly segmented, role-based network that deterministically supports automated containment and reproducible performance evaluation.

### Key Deliverables Delivered:
1. `configs/CORE-SW_security_acls.cfg`: Cisco IOS configuration script defining 7 Extended Named ACLs and SVI bindings.
2. `docs/02_access_control_matrix.md`: Global role-to-service access matrix covering all VLANs and containment states.
3. `docs/09_security_verification_matrix.md`: 20 security test cases (S1–S20) matching Member 4 evaluation scenarios.
4. `running-configs/CORE-SW_running_config.txt`: Updated master running configuration for CORE-SW.
5. `REPORT_MEMBER2.md`: Comprehensive engineering report.

---

## 2. Integration Specifications for Member 3 (Policy Engine)

Member 3's policy engine runs on `POLICY-HOST` (`192.168.40.50`) and communicates with access switches to enact dynamic port VLAN reassignments.

### 2.1 Preserved Communications for Policy Engine
- **SSH Management:** `POLICY-HOST` (`192.168.40.50`) has guaranteed SSH access (TCP port 22) through `CORE-SW` to:
  - `CORE-SW` SVI 40: `192.168.40.1`
  - `ACCESS-SW-A` SVI 40: `192.168.40.21`
  - `ACCESS-SW-B` SVI 40: `192.168.40.22`
  *(Enforced by top-priority rules in `ACL-VLAN40-ADMIN-IN`).*
- **DHCP Continuity:** When Member 3 executes `switchport access vlan 60` or `switchport access vlan 70`, the target host (`PC-STU2` on `Fa0/2`) issues a DHCP renew request. The SVI ACLs explicitly permit DHCP UDP ports 67/68 so the host successfully re-leases an IP in `192.168.60.x` or `192.168.70.x`.

### 2.2 Expected Network Behavior Across States

| Containment State | Host VLAN | Applied SVI Inbound ACL | Permitted Traffic | Denied Traffic |
|---|---|---|---|---|
| **NORMAL** | VLAN 10 (`192.168.10.x`) | `ACL-VLAN10-STUDENTS-IN` | DHCP, DNS, Internet Web/HTTPS, SRV-RESEARCH HTTP, SRV-REMEDIATE HTTP, ICMP | `SRV-ADMIN` (192.168.50.12), `SRV-DB` (192.168.50.11), Switch SSH (192.168.40.x:22), Other VLANs |
| **RESTRICTED** | VLAN 60 (`192.168.60.x`) | `ACL-VLAN60-RESTRICTED-IN` | DHCP, Gateway ICMP, Remediation DNS (`192.168.50.13:53`), Remediation Web (`192.168.50.13:80`) | **ALL** other internal servers, Internet, Switch SSH, All other subnets |
| **QUARANTINE** | VLAN 70 (`192.168.70.x`) | `ACL-VLAN70-QUARANTINE-IN` | DHCP, Gateway ICMP | **TOTAL LOCKDOWN** (0 routed packets to servers, internet, or internal subnets) |
| **RECOVERED** | VLAN 10 (`192.168.10.x`) | `ACL-VLAN10-STUDENTS-IN` | Full normal student permissions restored | Same as Normal state |

### 2.3 Containment Reassignment Command Sequences
When pushing containment from `POLICY-HOST`, Member 3 should issue:
```text
! Moving offender PC-STU2 (ACCESS-SW-A Fa0/2) to Restricted State:
configure terminal
interface FastEthernet0/2
 switchport access vlan 60
end

! Moving offender PC-STU2 to Total Quarantine State:
configure terminal
interface FastEthernet0/2
 switchport access vlan 70
end

! Restoring compliant PC-STU2 back to Normal State:
configure terminal
interface FastEthernet0/2
 switchport access vlan 10
end
```

---

## 3. Integration Specifications for Member 4 (Monitoring & Evaluation)

Member 4 can now remove all "blocked" placeholders in `monitoring/evaluate.py` and run full static vs. adaptive evaluations against `monitoring/scenarios.json`.

### 3.1 Mapping to Member 4 Scenario Catalog

| Scenario ID | Source Host | Target Destination & Port | Member 2 Expected Policy Outcome | Verification Notes for Member 4 |
|---|---|---|---|---|
| `authorized` | `PC-RES1` (VLAN 30) | `192.168.50.10:80` (HTTP) | **PERMIT (HTTP 200 OK)** | Permitted by `ACL-VLAN30-RESEARCH-IN`. Legitimate baseline benchmark. |
| `protected_access` | `PC-STU2` (VLAN 10) | `192.168.50.12:80` (HTTP) | **DENY (Connection Dropped)** | Dropped by Rule 14 of `ACL-VLAN10-STUDENTS-IN`. Demonstrates static protection. |
| `violations` | `PC-STU2` (VLAN 10) | `192.168.50.12:80` (HTTP) | **TRIGGER CONTAINMENT** | Member 3 engine detects repeated drops and shifts port to VLAN 60 / 70. |
| `legitimate_transition` | `PC-RES1` & `PC-STU2` | `192.168.50.10` & `192.168.50.13` | **ZERO COLLATERAL DISRUPTION** | While `PC-STU2` is quarantined, `PC-RES1` experiences 0% packet loss to `SRV-RESEARCH`. |
| `recovery` | `PC-STU2` | `192.168.50.13:80` $\rightarrow$ Restore $\rightarrow$ `203.0.113.2:80` | **PERMIT REMEDIATION $\rightarrow$ RESTORE NORMAL** | In VLAN 60, accesses remediation portal; after recovery to VLAN 10, normal internet access is restored. |
| `performance` | `PC-RES1` (VLAN 30) | `192.168.50.10` (ICMP Echo) | **PERMIT (RTT < 2 ms, 0% Loss)** | Permitted by Rule 3 of `ACL-VLAN30-RESEARCH-IN`. Suitable for 20-probe sample set. |

### 3.2 Distinguishing Real Policy Denial from Outage
Member 4 must verify:
1. When `PC-STU2` is denied access to `SRV-ADMIN` (`192.168.50.12`), test simultaneously from `PC-ADM1` (`192.168.40.100`) to confirm that `SRV-ADMIN` is healthy and responding.
2. In Simulation Mode, verify that the packet is dropped at `CORE-SW` SVI `Vlan10` with an ACL drop event (red X), proving ingress hardware filtering.
