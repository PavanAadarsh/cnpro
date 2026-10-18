# State Transition Test Plan

**Module:** BACSE203 – Computer Networks Lab  
**Member:** 3 – Adaptive Policy Engine  
**Document:** `tests/state_transition_test_plan.md`

---

## Pre-Test Setup Checklist

Before running any tests, verify the following prerequisites are met:

- [ ] POLICY-HOST IP is configured: 192.168.40.50 / 255.255.255.0 / GW 192.168.40.1
- [ ] POLICY-HOST can ping CORE-SW (192.168.40.1)
- [ ] POLICY-HOST can ping ACCESS-SW-A (192.168.40.21)
- [ ] POLICY-HOST can ping ACCESS-SW-B (192.168.40.22)
- [ ] SSH from POLICY-HOST succeeds to all three switches
- [ ] VLAN 60 and VLAN 70 exist in VLAN database on all switches
- [ ] DHCP pools for VLAN 60 (192.168.60.x) and VLAN 70 (192.168.70.x) are configured on CORE-SW
- [ ] ACLs for VLAN 60 and VLAN 70 SVIs are applied on CORE-SW
- [ ] All client PCs start in their home VLAN (normal state)

---

## Test Category 1: SSH Reachability

| Test ID | Device Under Test | Initial VLAN | Action Taken | Expected State | Expected VLAN | How to Verify | Pass/Fail |
|---------|------------------|-------------|-------------|---------------|--------------|--------------|-----------|
| SSH-01 | POLICY-HOST → CORE-SW | N/A | `ssh -l admin 192.168.40.1` from POLICY-HOST | SSH session established | N/A | CORE-SW prompt appears: `CORE-SW>` | |
| SSH-02 | POLICY-HOST → ACCESS-SW-A | N/A | `ssh -l admin 192.168.40.21` from POLICY-HOST | SSH session established | N/A | ACCESS-SW-A prompt appears: `ACCESS-SW-A>` | |
| SSH-03 | POLICY-HOST → ACCESS-SW-B | N/A | `ssh -l admin 192.168.40.22` from POLICY-HOST | SSH session established | N/A | ACCESS-SW-B prompt appears: `ACCESS-SW-B>` | |
| SSH-04 | PC-STU1 → any switch | VLAN 10 | `ssh -l admin 192.168.40.21` from PC-STU1 | SSH rejected | N/A | Connection refused or timed out (VTY access-class permits only 192.168.40.50) | |
| SSH-05 | CORE-SW VTY ACL | N/A | `show ip access-lists SSH-ONLY` on CORE-SW | Only 192.168.40.50 permitted | N/A | ACL shows `permit host 192.168.40.50` | |

---

## Test Category 2: Normal → Restricted Transition (Per Device)

### Instructions for each test:
1. SSH from POLICY-HOST to the indicated switch
2. Run the RESTRICT command block for the device
3. On the affected PC: `ipconfig /release` then `ipconfig /renew`
4. Verify new IP address is in 192.168.60.0/24
5. Check connectivity as specified

| Test ID | Device Under Test | Initial VLAN | Action Taken | Expected State | Expected VLAN | How to Verify | Pass/Fail |
|---------|------------------|-------------|-------------|---------------|--------------|--------------|-----------|
| NR-01 | PC-STU1 | 10 | SSH to ACCESS-SW-A, run `interface Fa0/1 / switchport access vlan 60` | RESTRICTED | 60 | `show int Fa0/1 switchport` → VLAN 60; PC gets 192.168.60.x IP | |
| NR-02 | PC-STU2 | 10 | SSH to ACCESS-SW-A, run `interface Fa0/2 / switchport access vlan 60` | RESTRICTED | 60 | `show int Fa0/2 switchport` → VLAN 60; PC gets 192.168.60.x IP | |
| NR-03 | PC-FAC1 | 20 | SSH to ACCESS-SW-A, run `interface Fa0/3 / switchport access vlan 60` | RESTRICTED | 60 | `show int Fa0/3 switchport` → VLAN 60; PC gets 192.168.60.x IP | |
| NR-04 | PC-FAC2 | 20 | SSH to ACCESS-SW-A, run `interface Fa0/4 / switchport access vlan 60` | RESTRICTED | 60 | `show int Fa0/4 switchport` → VLAN 60; PC gets 192.168.60.x IP | |
| NR-05 | PC-ADM1 | 40 | SSH to ACCESS-SW-A, run `interface Fa0/5 / switchport access vlan 60` | RESTRICTED | 60 | `show int Fa0/5 switchport` → VLAN 60; PC gets 192.168.60.x IP | |
| NR-06 | PC-ADM2 | 40 | SSH to ACCESS-SW-A, run `interface Fa0/6 / switchport access vlan 60` | RESTRICTED | 60 | `show int Fa0/6 switchport` → VLAN 60; PC gets 192.168.60.x IP | |
| NR-07 | PC-RES1 | 30 | SSH to ACCESS-SW-B, run `interface Fa0/1 / switchport access vlan 60` | RESTRICTED | 60 | `show int Fa0/1 switchport` → VLAN 60; PC gets 192.168.60.x IP | |
| NR-08 | PC-RES2 | 30 | SSH to ACCESS-SW-B, run `interface Fa0/2 / switchport access vlan 60` | RESTRICTED | 60 | `show int Fa0/2 switchport` → VLAN 60; PC gets 192.168.60.x IP | |

---

## Test Category 3: Restricted → Quarantine Escalation

| Test ID | Device Under Test | Initial VLAN | Action Taken | Expected State | Expected VLAN | How to Verify | Pass/Fail |
|---------|------------------|-------------|-------------|---------------|--------------|--------------|-----------|
| RQ-01 | PC-STU1 | 60 (RESTRICTED) | SSH to ACCESS-SW-A, run `interface Fa0/1 / switchport access vlan 70` | QUARANTINE | 70 | `show int Fa0/1 switchport` → VLAN 70; PC gets 192.168.70.x IP | |
| RQ-02 | PC-STU2 | 60 (RESTRICTED) | SSH to ACCESS-SW-A, run `interface Fa0/2 / switchport access vlan 70` | QUARANTINE | 70 | `show int Fa0/2 switchport` → VLAN 70; PC gets 192.168.70.x IP | |
| RQ-03 | PC-FAC1 | 60 (RESTRICTED) | SSH to ACCESS-SW-A, run `interface Fa0/3 / switchport access vlan 70` | QUARANTINE | 70 | `show int Fa0/3 switchport` → VLAN 70; PC gets 192.168.70.x IP | |
| RQ-04 | PC-FAC2 | 60 (RESTRICTED) | SSH to ACCESS-SW-A, run `interface Fa0/4 / switchport access vlan 70` | QUARANTINE | 70 | `show int Fa0/4 switchport` → VLAN 70; PC gets 192.168.70.x IP | |
| RQ-05 | PC-ADM1 | 60 (RESTRICTED) | SSH to ACCESS-SW-A, run `interface Fa0/5 / switchport access vlan 70` | QUARANTINE | 70 | `show int Fa0/5 switchport` → VLAN 70; PC gets 192.168.70.x IP | |
| RQ-06 | PC-ADM2 | 60 (RESTRICTED) | SSH to ACCESS-SW-A, run `interface Fa0/6 / switchport access vlan 70` | QUARANTINE | 70 | `show int Fa0/6 switchport` → VLAN 70; PC gets 192.168.70.x IP | |
| RQ-07 | PC-RES1 | 60 (RESTRICTED) | SSH to ACCESS-SW-B, run `interface Fa0/1 / switchport access vlan 70` | QUARANTINE | 70 | `show int Fa0/1 switchport` → VLAN 70; PC gets 192.168.70.x IP | |
| RQ-08 | PC-RES2 | 60 (RESTRICTED) | SSH to ACCESS-SW-B, run `interface Fa0/2 / switchport access vlan 70` | QUARANTINE | 70 | `show int Fa0/2 switchport` → VLAN 70; PC gets 192.168.70.x IP | |

---

## Test Category 4: Quarantine → Restore (Recovery)

| Test ID | Device Under Test | Initial VLAN | Action Taken | Expected State | Expected VLAN | How to Verify | Pass/Fail |
|---------|------------------|-------------|-------------|---------------|--------------|--------------|-----------|
| QN-01 | PC-STU1 | 70 (QUARANTINE) | SSH to ACCESS-SW-A, run `interface Fa0/1 / switchport access vlan 10` | NORMAL | 10 | `show int Fa0/1 switchport` → VLAN 10; PC gets 192.168.10.x IP | |
| QN-02 | PC-STU2 | 70 (QUARANTINE) | SSH to ACCESS-SW-A, run `interface Fa0/2 / switchport access vlan 10` | NORMAL | 10 | `show int Fa0/2 switchport` → VLAN 10; PC gets 192.168.10.x IP | |
| QN-03 | PC-FAC1 | 70 (QUARANTINE) | SSH to ACCESS-SW-A, run `interface Fa0/3 / switchport access vlan 20` | NORMAL | 20 | `show int Fa0/3 switchport` → VLAN 20; PC gets 192.168.20.x IP | |
| QN-04 | PC-FAC2 | 70 (QUARANTINE) | SSH to ACCESS-SW-A, run `interface Fa0/4 / switchport access vlan 20` | NORMAL | 20 | `show int Fa0/4 switchport` → VLAN 20; PC gets 192.168.20.x IP | |
| QN-05 | PC-ADM1 | 70 (QUARANTINE) | SSH to ACCESS-SW-A, run `interface Fa0/5 / switchport access vlan 40` | NORMAL | 40 | `show int Fa0/5 switchport` → VLAN 40; PC gets 192.168.40.x IP | |
| QN-06 | PC-ADM2 | 70 (QUARANTINE) | SSH to ACCESS-SW-A, run `interface Fa0/6 / switchport access vlan 40` | NORMAL | 40 | `show int Fa0/6 switchport` → VLAN 40; PC gets 192.168.40.x IP | |
| QN-07 | PC-RES1 | 70 (QUARANTINE) | SSH to ACCESS-SW-B, run `interface Fa0/1 / switchport access vlan 30` | NORMAL | 30 | `show int Fa0/1 switchport` → VLAN 30; PC gets 192.168.30.x IP | |
| QN-08 | PC-RES2 | 70 (QUARANTINE) | SSH to ACCESS-SW-B, run `interface Fa0/2 / switchport access vlan 30` | NORMAL | 30 | `show int Fa0/2 switchport` → VLAN 30; PC gets 192.168.30.x IP | |

---

## Test Category 5: Restricted Device Cannot Reach Internal Servers

> Use any device in RESTRICTED state (VLAN 60) to run these tests.  
> Example: Restrict PC-STU1, then run pings from PC-STU1.

| Test ID | Device Under Test | Initial VLAN | Action Taken | Expected State | Expected VLAN | How to Verify | Pass/Fail |
|---------|------------------|-------------|-------------|---------------|--------------|--------------|-----------|
| RS-01 | PC-STU1 | 60 (RESTRICTED) | `ping 192.168.50.10` from PC-STU1 | Blocked | 60 | Ping fails (timeout / destination unreachable) | |
| RS-02 | PC-STU1 | 60 (RESTRICTED) | `ping 192.168.50.11` from PC-STU1 | Blocked | 60 | Ping fails (timeout / destination unreachable) | |
| RS-03 | PC-STU1 | 60 (RESTRICTED) | `ping 192.168.50.12` from PC-STU1 | Blocked | 60 | Ping fails (timeout / destination unreachable) | |
| RS-04 | PC-STU1 | 60 (RESTRICTED) | `ping 192.168.10.2` from PC-STU1 (another student VLAN host) | Blocked | 60 | Ping fails | |
| RS-05 | PC-STU1 | 60 (RESTRICTED) | `ping 192.168.20.1` from PC-STU1 (FACULTY subnet gateway) | Blocked | 60 | Ping fails | |
| RS-06 | PC-STU1 | 60 (RESTRICTED) | `ping 8.8.8.8` from PC-STU1 (internet) | Allowed | 60 | Ping succeeds (internet accessible from RESTRICTED) | |
| RS-07 | PC-STU1 | 60 (RESTRICTED) | `ping 192.168.50.13` from PC-STU1 (SRV-REMEDIATE) | Allowed | 60 | Ping succeeds | |

---

## Test Category 6: Quarantine Device Cannot Reach Internet

> Use any device in QUARANTINE state (VLAN 70) to run these tests.  
> Example: Quarantine PC-STU1, then run pings from PC-STU1.

| Test ID | Device Under Test | Initial VLAN | Action Taken | Expected State | Expected VLAN | How to Verify | Pass/Fail |
|---------|------------------|-------------|-------------|---------------|--------------|--------------|-----------|
| QI-01 | PC-STU1 | 70 (QUARANTINE) | `ping 8.8.8.8` from PC-STU1 | Blocked | 70 | Ping fails (internet blocked in QUARANTINE) | |
| QI-02 | PC-STU1 | 70 (QUARANTINE) | `ping 1.1.1.1` from PC-STU1 | Blocked | 70 | Ping fails | |
| QI-03 | PC-STU1 | 70 (QUARANTINE) | `ping 192.168.50.10` from PC-STU1 (SRV-RESEARCH) | Blocked | 70 | Ping fails | |
| QI-04 | PC-STU1 | 70 (QUARANTINE) | `ping 192.168.50.11` from PC-STU1 (SRV-DB) | Blocked | 70 | Ping fails | |
| QI-05 | PC-STU1 | 70 (QUARANTINE) | `ping 192.168.50.12` from PC-STU1 (SRV-ADMIN) | Blocked | 70 | Ping fails | |
| QI-06 | PC-STU1 | 70 (QUARANTINE) | `ping 192.168.10.1` from PC-STU1 (STUDENTS gateway) | Blocked | 70 | Ping fails | |

---

## Test Category 7: Quarantined Device CAN Reach SRV-REMEDIATE

> Continue with any device in QUARANTINE state (VLAN 70).

| Test ID | Device Under Test | Initial VLAN | Action Taken | Expected State | Expected VLAN | How to Verify | Pass/Fail |
|---------|------------------|-------------|-------------|---------------|--------------|--------------|-----------|
| QR-01 | PC-STU1 | 70 (QUARANTINE) | `ping 192.168.50.13` from PC-STU1 | Allowed | 70 | Ping succeeds (ICMP to SRV-REMEDIATE allowed) | |
| QR-02 | PC-STU1 | 70 (QUARANTINE) | Open browser to `http://192.168.50.13` from PC-STU1 | Allowed | 70 | HTTP page loads (TCP 80 to SRV-REMEDIATE allowed) | |
| QR-03 | PC-RES1 | 70 (QUARANTINE) | `ping 192.168.50.13` from PC-RES1 | Allowed | 70 | Ping succeeds | |
| QR-04 | PC-FAC1 | 70 (QUARANTINE) | `ping 192.168.50.13` from PC-FAC1 | Allowed | 70 | Ping succeeds | |

---

## Test Category 8: VLAN Assignment Persistence (After Write Memory)

| Test ID | Device Under Test | Initial VLAN | Action Taken | Expected State | Expected VLAN | How to Verify | Pass/Fail |
|---------|------------------|-------------|-------------|---------------|--------------|--------------|-----------|
| VP-01 | PC-STU1 | 60 (RESTRICTED) | Reload ACCESS-SW-A (`reload` on switch) | RESTRICTED (persists) | 60 | After reload: `show int Fa0/1 switchport` still shows VLAN 60 | |
| VP-02 | PC-RES2 | 70 (QUARANTINE) | Reload ACCESS-SW-B (`reload` on switch) | QUARANTINE (persists) | 70 | After reload: `show int Fa0/2 switchport` still shows VLAN 70 | |

---

## Test Results Summary Sheet

| Category | Total Tests | Passed | Failed | Notes |
|----------|------------|--------|--------|-------|
| SSH Reachability | 5 | | | |
| Normal → Restricted | 8 | | | |
| Restricted → Quarantine | 8 | | | |
| Quarantine → Restore | 8 | | | |
| Restricted blocks internal | 7 | | | |
| Quarantine blocks internet | 6 | | | |
| Quarantine allows SRV-REMEDIATE | 4 | | | |
| VLAN persistence after reload | 2 | | | |
| **TOTAL** | **48** | | | |

---

## Common Failure Modes & Resolution

| Failure | Likely Cause | Resolution |
|---------|-------------|-----------|
| PC does not get new IP after VLAN change | DHCP pool for VLAN 60/70 not configured | Verify `ip dhcp pool RESTRICTED` / `QUARANTINE` on CORE-SW |
| Ping to SRV-REMEDIATE fails from QUARANTINE | ACL on VLAN 70 SVI not applied | Apply `ip access-group ACL-QUARANTINE-IN in` on `interface vlan 70` |
| Internet works from QUARANTINE | ACL not denying non-RFC1918 traffic | Review and fix ACL-QUARANTINE-IN |
| SSH from POLICY-HOST fails | IP connectivity or VTY config issue | Check `ping 192.168.40.21` from POLICY-HOST; verify SSH-ONLY ACL |
| VLAN assignment does not persist after reload | `write memory` not executed | Re-run containment command and execute `write memory` |

---

*Document end — `tests/state_transition_test_plan.md`*
