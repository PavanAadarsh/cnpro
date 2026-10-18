# Adaptive Policy Engine – Detailed Design Document

**Module:** BACSE203 – Computer Networks Lab  
**Member:** 3 – Adaptive Policy Engine  
**Document:** `configs/policy_engine_design.md`

---

## 1. Device States & VLAN Assignments

### 1.1 State Definitions

```
┌─────────────────────────────────────────────────────────────────────┐
│  STATE         │ VLAN │ SUBNET           │ DESCRIPTION              │
├─────────────────────────────────────────────────────────────────────┤
│  NORMAL        │ home │ per device       │ Full permitted access     │
│  RESTRICTED    │  60  │ 192.168.60.0/24  │ Internet + remediate only │
│  QUARANTINE    │  70  │ 192.168.70.0/24  │ Remediate only, no inet   │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Per-Device State Table

| Device | Home VLAN | Normal Subnet | Restricted VLAN | Quarantine VLAN |
|--------|-----------|--------------|-----------------|-----------------|
| PC-STU1 | 10 | 192.168.10.0/24 | 60 | 70 |
| PC-STU2 | 10 | 192.168.10.0/24 | 60 | 70 |
| PC-FAC1 | 20 | 192.168.20.0/24 | 60 | 70 |
| PC-FAC2 | 20 | 192.168.20.0/24 | 60 | 70 |
| PC-ADM1 | 40 | 192.168.40.0/24 | 60 | 70 |
| PC-ADM2 | 40 | 192.168.40.0/24 | 60 | 70 |
| PC-RES1 | 30 | 192.168.30.0/24 | 60 | 70 |
| PC-RES2 | 30 | 192.168.30.0/24 | 60 | 70 |

---

## 2. Threshold Definitions

### 2.1 NORMAL → RESTRICTED Triggers

| Threshold ID | Name | Condition | Detection Method |
|---|---|---|---|
| TH-01 | Auth-Failure Burst | ≥ 3 failed auth attempts to any server in a 60-second window | SSH logs on servers / syslog | 
| TH-02 | Port-Scan Detection | > 20 unique destination ports contacted in 10 seconds | NetFlow / CORE-SW syslog |
| TH-03-A | Policy-Repeat | Device re-enters RESTRICTED state 2× within 1 hour of restoration | Policy state log |
| TH-06 | Excessive Bandwidth | Sustained > 80% of link capacity for > 5 minutes to a single internal server | Interface counters |

### 2.2 NORMAL → QUARANTINE (Direct) Triggers

| Threshold ID | Name | Condition |
|---|---|---|
| TH-04 | IP Spoofing | Traffic sourced from VLAN 60/70 address space while device is in NORMAL state |
| TH-07 | Malware Signature | Traffic matches known malware C2 patterns (simulated by operator in lab) |

### 2.3 RESTRICTED → QUARANTINE Escalation Triggers

| Threshold ID | Name | Condition |
|---|---|---|
| TH-03-B | Persistent Violation | Device in RESTRICTED continues triggering TH-01 or TH-02 for > 30 min |
| TH-05 | Repeat Offender | Device has been RESTRICTED 2× within a single 1-hour window |

### 2.4 Recovery Conditions

| Recovery ID | From State | Condition | Method |
|---|---|---|---|
| REC-01 | RESTRICTED | Manual operator clear | Operator runs restore cmd from POLICY-HOST |
| REC-02 | RESTRICTED | 30-minute hold timer expires with no new threshold events | Operator monitors and runs restore cmd |
| REC-03 | QUARANTINE | Manual operator clear | Operator runs restore cmd from POLICY-HOST |
| REC-04 | QUARANTINE | 2-hour hold timer expires with no new threshold events | Operator monitors and runs restore cmd |

> **Lab Note:** In simulation, all thresholds are manually triggered by the operator. The POLICY-HOST CLI is the "automation engine". Operators simulate TH-01 by attempting failed SSH connections, and simulate recovery by waiting the prescribed hold time before issuing restore commands.

---

## 3. Traffic Policy per State

### 3.1 NORMAL State (Home VLAN)

Traffic controlled by Member 1's existing inter-VLAN ACLs on CORE-SW. No additional restrictions from Member 3 except inheriting the baseline.

| Source VLAN | Allowed Destinations | Denied Destinations |
|-------------|---------------------|---------------------|
| STUDENTS (10) | SERVERS (50) – HTTP/HTTPS, RESEARCH (30) – read only | ADMIN (40), direct inter-VLAN between students |
| FACULTY (20) | SERVERS (50), RESEARCH (30), STUDENTS (10) – read | ADMIN (40) |
| RESEARCH (30) | SERVERS (50), internet | ADMIN (40) |
| ADMIN (40) | All VLANs | — |

### 3.2 RESTRICTED State (VLAN 60)

ACL applied on CORE-SW SVI interface VLAN 60 (inbound):

```ios
! CORE-SW – ACL for VLAN 60 (RESTRICTED) – defined by Member 1
ip access-list extended ACL-RESTRICTED-IN
 remark Allow DHCP
 permit udp any host 255.255.255.255 eq 67
 remark Allow ICMP to gateway only
 permit icmp any host 192.168.60.1
 remark Allow DNS to internet
 permit udp any any eq 53
 remark Allow HTTP/HTTPS to internet (not to RFC1918)
 permit tcp any any eq 80
 permit tcp any any eq 443
 remark Allow all traffic to SRV-REMEDIATE
 permit ip any host 192.168.50.13
 remark Deny everything else
 deny ip any any log
```

**Permitted by State (summary):**

| Traffic Type | Destination | Permitted? |
|---|---|---|
| DHCP | Broadcast | ✅ Yes |
| ICMP | Gateway (192.168.60.1) | ✅ Yes |
| HTTP/HTTPS (80/443) | Internet (non-RFC1918) | ✅ Yes |
| DNS (53) | Any | ✅ Yes |
| Any protocol | SRV-REMEDIATE (192.168.50.13) | ✅ Yes |
| Any | Internal servers (192.168.50.10–12) | ❌ No |
| Any | User VLANs (10,20,30,40) | ❌ No |

### 3.3 QUARANTINE State (VLAN 70)

ACL applied on CORE-SW SVI interface VLAN 70 (inbound):

```ios
! CORE-SW – ACL for VLAN 70 (QUARANTINE) – defined by Member 1
ip access-list extended ACL-QUARANTINE-IN
 remark Allow DHCP
 permit udp any host 255.255.255.255 eq 67
 remark Allow ICMP to gateway only
 permit icmp any host 192.168.70.1
 remark Allow HTTP to SRV-REMEDIATE only
 permit tcp any host 192.168.50.13 eq 80
 remark Allow ICMP to SRV-REMEDIATE only
 permit icmp any host 192.168.50.13
 remark Deny everything else
 deny ip any any log
```

**Permitted by State (summary):**

| Traffic Type | Destination | Permitted? |
|---|---|---|
| DHCP | Broadcast | ✅ Yes |
| ICMP | Gateway (192.168.70.1) | ✅ Yes |
| HTTP (80) | SRV-REMEDIATE (192.168.50.13) | ✅ Yes |
| ICMP | SRV-REMEDIATE (192.168.50.13) | ✅ Yes |
| Any | Internet | ❌ No |
| Any | All other internal servers | ❌ No |
| Any | All user VLANs | ❌ No |

---

## 4. Full Containment Command Table

> SSH from POLICY-HOST to the target switch, then run the commands below.  
> All commands are executed under `configure terminal` mode.

### 4.1 ACCESS-SW-A Devices (SSH to 192.168.40.21)

| Device | Port | Home VLAN | Restrict Command | Quarantine Command | Restore Command |
|--------|------|-----------|------------------|--------------------|-----------------|
| PC-STU1 | Fa0/1 | 10 | `interface Fa0/1` / `switchport access vlan 60` | `interface Fa0/1` / `switchport access vlan 70` | `interface Fa0/1` / `switchport access vlan 10` |
| PC-STU2 | Fa0/2 | 10 | `interface Fa0/2` / `switchport access vlan 60` | `interface Fa0/2` / `switchport access vlan 70` | `interface Fa0/2` / `switchport access vlan 10` |
| PC-FAC1 | Fa0/3 | 20 | `interface Fa0/3` / `switchport access vlan 60` | `interface Fa0/3` / `switchport access vlan 70` | `interface Fa0/3` / `switchport access vlan 20` |
| PC-FAC2 | Fa0/4 | 20 | `interface Fa0/4` / `switchport access vlan 60` | `interface Fa0/4` / `switchport access vlan 70` | `interface Fa0/4` / `switchport access vlan 20` |
| PC-ADM1 | Fa0/5 | 40 | `interface Fa0/5` / `switchport access vlan 60` | `interface Fa0/5` / `switchport access vlan 70` | `interface Fa0/5` / `switchport access vlan 40` |
| PC-ADM2 | Fa0/6 | 40 | `interface Fa0/6` / `switchport access vlan 60` | `interface Fa0/6` / `switchport access vlan 70` | `interface Fa0/6` / `switchport access vlan 40` |

### 4.2 ACCESS-SW-B Devices (SSH to 192.168.40.22)

| Device | Port | Home VLAN | Restrict Command | Quarantine Command | Restore Command |
|--------|------|-----------|------------------|--------------------|-----------------|
| PC-RES1 | Fa0/1 | 30 | `interface Fa0/1` / `switchport access vlan 60` | `interface Fa0/1` / `switchport access vlan 70` | `interface Fa0/1` / `switchport access vlan 30` |
| PC-RES2 | Fa0/2 | 30 | `interface Fa0/2` / `switchport access vlan 60` | `interface Fa0/2` / `switchport access vlan 70` | `interface Fa0/2` / `switchport access vlan 30` |

---

## 5. Switch SSH Target Reference

| Switch | Management IP | SSH Command from POLICY-HOST |
|--------|--------------|------------------------------|
| CORE-SW | 192.168.40.1 | `ssh -l admin 192.168.40.1` |
| ACCESS-SW-A | 192.168.40.21 | `ssh -l admin 192.168.40.21` |
| ACCESS-SW-B | 192.168.40.22 | `ssh -l admin 192.168.40.22` |

---

## 6. Verification Commands

### Post-Containment Verification (on switch after SSH)

```ios
! Check VLAN assignment on a specific port
show interfaces FastEthernet0/1 switchport

! Check all access port VLAN assignments
show interfaces status

! Check VLAN membership
show vlan brief

! Check MAC address table for a VLAN
show mac address-table vlan 60
show mac address-table vlan 70
```

### Post-Restore Verification (on affected PC)

```
! Release and renew DHCP to confirm new VLAN address
ipconfig /release
ipconfig /renew
ipconfig
```

---

*Document end — `configs/policy_engine_design.md`*
