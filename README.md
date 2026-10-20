# Member 3 – Adaptive Policy Engine

**BACSE203 – Computer Networks Lab Project**

---

## Role Description

Member 3 is responsible for the **Adaptive Policy Engine** of the university research network simulation. The engine dynamically enforces security policy by detecting violations (simulated manually in the lab) and moving offending devices into containment VLANs via SSH-driven switchport reassignment — without modifying ACLs or ARP tables.

**Control Node:** POLICY-HOST (`192.168.40.50`, VLAN 40, ACCESS-SW-A Fa0/7)

---

## Device States

| State | VLAN | Subnet | Description |
|-------|------|--------|-------------|
| **NORMAL** | Home (10/20/30/40) | Per VLAN | Full policy-permitted access |
| **RESTRICTED** | 60 | 192.168.60.0/24 | Internet + SRV-REMEDIATE only |
| **QUARANTINE** | 70 | 192.168.70.0/24 | SRV-REMEDIATE only, no internet |

---

## Folder Structure

```
cnpro-member3-adaptive-policy/
├── README.md                          ← This file
├── REPORT_MEMBER3.md                  ← Full technical report
├── simulate_event.py                  ← CLI engine controller & injection tool
├── policy_engine/                     ← Python controller package (state, thresholds, SSH, recovery)
├── docs/
│   ├── ENGINE_RUNTIME_AND_RECONCILIATION.md ← Runtime launch, event logging contract & reconciled thresholds
│   ├── MEMBER4_RECONCILIATION_RESPONSE.md   ← Direct response to Member 4 questions & reconciliation audit
│   ├── MEMBER4_AUDIT_RESOLUTION.md          ← Point-by-point audit compliance resolution
│   └── LIVE_NETWORK_ENFORCEMENT_EVIDENCE.md  ← Live CLI outputs, switchport verification & DHCP renew evidence
├── configs/
│   ├── policy_engine_design.md        ← States, thresholds, ACL details, command table
│   ├── POLICY-HOST_configuration.md   ← Static IP setup, SSH connection guide
│   └── containment_commands.md        ← Copy-paste IOS commands for each device
└── tests/
    ├── test_policy_engine.py          ← 49 automated unit/integration tests
    └── state_transition_test_plan.md  ← 48 structured test cases
```

---

## How to Use the Containment Commands

### Step 1 – Open SSH from POLICY-HOST

```
! For ACCESS-SW-A devices (PC-STU1/2, PC-FAC1/2, PC-ADM1/2):
ssh -l admin 192.168.40.21

! For ACCESS-SW-B devices (PC-RES1/2):
ssh -l admin 192.168.40.22

! For CORE-SW management:
ssh -l admin 192.168.40.1

! Password for all: Admin@123
```

### Step 2 – Enter enable + config mode

```ios
enable
! Password: Admin@123
configure terminal
```

### Step 3 – Paste the containment block

Find the device in [`configs/containment_commands.md`](configs/containment_commands.md) and copy-paste the relevant block:
- 🔴 **RESTRICT** → moves port to VLAN 60
- 🟠 **QUARANTINE** → moves port to VLAN 70
- 🟢 **RESTORE** → returns port to home VLAN

### Step 4 – Verify

```ios
show interfaces FastEthernet0/X switchport
! Look for: Access Mode VLAN: 60 / 70 / <home>
```

---

## Device Port Reference

| Device | Switch | Port | Home VLAN |
|--------|--------|------|-----------|
| PC-STU1 | ACCESS-SW-A | Fa0/1 | 10 |
| PC-STU2 | ACCESS-SW-A | Fa0/2 | 10 |
| PC-FAC1 | ACCESS-SW-A | Fa0/3 | 20 |
| PC-FAC2 | ACCESS-SW-A | Fa0/4 | 20 |
| PC-ADM1 | ACCESS-SW-A | Fa0/5 | 40 |
| PC-ADM2 | ACCESS-SW-A | Fa0/6 | 40 |
| POLICY-HOST | ACCESS-SW-A | Fa0/7 | 40 (static 192.168.40.50) |
| PC-RES1 | ACCESS-SW-B | Fa0/1 | 30 |
| PC-RES2 | ACCESS-SW-B | Fa0/2 | 30 |

---

## Test Plan Summary

The test plan in [`tests/state_transition_test_plan.md`](tests/state_transition_test_plan.md) contains **48 test cases** across 8 categories:

| # | Category | Tests |
|---|----------|-------|
| 1 | SSH Reachability | 5 |
| 2 | Normal → Restricted | 8 |
| 3 | Restricted → Quarantine | 8 |
| 4 | Quarantine → Restore (Recovery) | 8 |
| 5 | Restricted blocks internal servers | 7 |
| 6 | Quarantine blocks internet | 6 |
| 7 | Quarantine allows SRV-REMEDIATE | 4 |
| 8 | VLAN persistence after reload | 2 |

---

## Dependencies on Member 1

This module **requires** the following from Member 1's baseline:

- VLAN 60 and 70 defined on all switches and trunks
- DHCP pools for VLAN 60 (192.168.60.0/24) and VLAN 70 (192.168.70.0/24) on CORE-SW
- ACLs applied to VLAN 60 and 70 SVIs on CORE-SW
- SSH `access-class SSH-ONLY` (permit host 192.168.40.50) on all VTY lines
- Local user `admin` with `privilege 15 secret Admin@123` on all switches
- CORE-SW SVI VLAN 40 at 192.168.40.1

---

## Key Files

| File | Purpose |
|------|---------|
| [`REPORT_MEMBER3.md`](REPORT_MEMBER3.md) | Full technical report for submission |
| [`configs/policy_engine_design.md`](configs/policy_engine_design.md) | Design doc: states, thresholds, ACLs, command table |
| [`configs/POLICY-HOST_configuration.md`](configs/POLICY-HOST_configuration.md) | POLICY-HOST static IP and SSH setup |
| [`configs/containment_commands.md`](configs/containment_commands.md) | Ready-to-paste IOS commands |
| [`tests/state_transition_test_plan.md`](tests/state_transition_test_plan.md) | 48-case structured test sheet |

---

*BACSE203 – Computer Networks Lab | Member 3 – Adaptive Policy Engine*
