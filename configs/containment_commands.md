# Containment Commands Reference

**Module:** BACSE203 – Computer Networks Lab  
**Member:** 3 – Adaptive Policy Engine  
**Document:** `configs/containment_commands.md`

---

## Usage Instructions

1. From **POLICY-HOST** (192.168.40.50), SSH into the target switch
2. Enter enable mode
3. Enter global configuration mode
4. Paste the appropriate block below
5. Run `write memory` to save
6. Verify with `show interfaces FastEthernet0/X switchport`

---

## SSH Preamble (run once per session)

### To ACCESS-SW-A (contains PC-STU1, PC-STU2, PC-FAC1, PC-FAC2, PC-ADM1, PC-ADM2)
```
ssh -l admin 192.168.40.21
! Password: Admin@123
enable
! Password: Admin@123
configure terminal
```

### To ACCESS-SW-B (contains PC-RES1, PC-RES2)
```
ssh -l admin 192.168.40.22
! Password: Admin@123
enable
! Password: Admin@123
configure terminal
```

---

## ACCESS-SW-A — Containment Commands

### ══════════════════════════════════════
### PC-STU1 | Fa0/1 | Home VLAN: 10
### ══════════════════════════════════════

#### 🔴 RESTRICT (move to VLAN 60)
```ios
interface FastEthernet0/1
 description PC-STU1 [RESTRICTED]
 switchport access vlan 60
end
write memory
show interfaces FastEthernet0/1 switchport
```

#### 🟠 QUARANTINE (move to VLAN 70)
```ios
interface FastEthernet0/1
 description PC-STU1 [QUARANTINE]
 switchport access vlan 70
end
write memory
show interfaces FastEthernet0/1 switchport
```

#### 🟢 RESTORE (return to VLAN 10)
```ios
interface FastEthernet0/1
 description PC-STU1
 switchport access vlan 10
end
write memory
show interfaces FastEthernet0/1 switchport
```

---

### ══════════════════════════════════════
### PC-STU2 | Fa0/2 | Home VLAN: 10
### ══════════════════════════════════════

#### 🔴 RESTRICT (move to VLAN 60)
```ios
interface FastEthernet0/2
 description PC-STU2 [RESTRICTED]
 switchport access vlan 60
end
write memory
show interfaces FastEthernet0/2 switchport
```

#### 🟠 QUARANTINE (move to VLAN 70)
```ios
interface FastEthernet0/2
 description PC-STU2 [QUARANTINE]
 switchport access vlan 70
end
write memory
show interfaces FastEthernet0/2 switchport
```

#### 🟢 RESTORE (return to VLAN 10)
```ios
interface FastEthernet0/2
 description PC-STU2
 switchport access vlan 10
end
write memory
show interfaces FastEthernet0/2 switchport
```

---

### ══════════════════════════════════════
### PC-FAC1 | Fa0/3 | Home VLAN: 20
### ══════════════════════════════════════

#### 🔴 RESTRICT (move to VLAN 60)
```ios
interface FastEthernet0/3
 description PC-FAC1 [RESTRICTED]
 switchport access vlan 60
end
write memory
show interfaces FastEthernet0/3 switchport
```

#### 🟠 QUARANTINE (move to VLAN 70)
```ios
interface FastEthernet0/3
 description PC-FAC1 [QUARANTINE]
 switchport access vlan 70
end
write memory
show interfaces FastEthernet0/3 switchport
```

#### 🟢 RESTORE (return to VLAN 20)
```ios
interface FastEthernet0/3
 description PC-FAC1
 switchport access vlan 20
end
write memory
show interfaces FastEthernet0/3 switchport
```

---

### ══════════════════════════════════════
### PC-FAC2 | Fa0/4 | Home VLAN: 20
### ══════════════════════════════════════

#### 🔴 RESTRICT (move to VLAN 60)
```ios
interface FastEthernet0/4
 description PC-FAC2 [RESTRICTED]
 switchport access vlan 60
end
write memory
show interfaces FastEthernet0/4 switchport
```

#### 🟠 QUARANTINE (move to VLAN 70)
```ios
interface FastEthernet0/4
 description PC-FAC2 [QUARANTINE]
 switchport access vlan 70
end
write memory
show interfaces FastEthernet0/4 switchport
```

#### 🟢 RESTORE (return to VLAN 20)
```ios
interface FastEthernet0/4
 description PC-FAC2
 switchport access vlan 20
end
write memory
show interfaces FastEthernet0/4 switchport
```

---

### ══════════════════════════════════════
### PC-ADM1 | Fa0/5 | Home VLAN: 40
### ══════════════════════════════════════

#### 🔴 RESTRICT (move to VLAN 60)
```ios
interface FastEthernet0/5
 description PC-ADM1 [RESTRICTED]
 switchport access vlan 60
end
write memory
show interfaces FastEthernet0/5 switchport
```

#### 🟠 QUARANTINE (move to VLAN 70)
```ios
interface FastEthernet0/5
 description PC-ADM1 [QUARANTINE]
 switchport access vlan 70
end
write memory
show interfaces FastEthernet0/5 switchport
```

#### 🟢 RESTORE (return to VLAN 40)
```ios
interface FastEthernet0/5
 description PC-ADM1
 switchport access vlan 40
end
write memory
show interfaces FastEthernet0/5 switchport
```

---

### ══════════════════════════════════════
### PC-ADM2 | Fa0/6 | Home VLAN: 40
### ══════════════════════════════════════

#### 🔴 RESTRICT (move to VLAN 60)
```ios
interface FastEthernet0/6
 description PC-ADM2 [RESTRICTED]
 switchport access vlan 60
end
write memory
show interfaces FastEthernet0/6 switchport
```

#### 🟠 QUARANTINE (move to VLAN 70)
```ios
interface FastEthernet0/6
 description PC-ADM2 [QUARANTINE]
 switchport access vlan 70
end
write memory
show interfaces FastEthernet0/6 switchport
```

#### 🟢 RESTORE (return to VLAN 40)
```ios
interface FastEthernet0/6
 description PC-ADM2
 switchport access vlan 40
end
write memory
show interfaces FastEthernet0/6 switchport
```

---

## ACCESS-SW-B — Containment Commands

### ══════════════════════════════════════
### PC-RES1 | Fa0/1 | Home VLAN: 30
### ══════════════════════════════════════

#### 🔴 RESTRICT (move to VLAN 60)
```ios
interface FastEthernet0/1
 description PC-RES1 [RESTRICTED]
 switchport access vlan 60
end
write memory
show interfaces FastEthernet0/1 switchport
```

#### 🟠 QUARANTINE (move to VLAN 70)
```ios
interface FastEthernet0/1
 description PC-RES1 [QUARANTINE]
 switchport access vlan 70
end
write memory
show interfaces FastEthernet0/1 switchport
```

#### 🟢 RESTORE (return to VLAN 30)
```ios
interface FastEthernet0/1
 description PC-RES1
 switchport access vlan 30
end
write memory
show interfaces FastEthernet0/1 switchport
```

---

### ══════════════════════════════════════
### PC-RES2 | Fa0/2 | Home VLAN: 30
### ══════════════════════════════════════

#### 🔴 RESTRICT (move to VLAN 60)
```ios
interface FastEthernet0/2
 description PC-RES2 [RESTRICTED]
 switchport access vlan 60
end
write memory
show interfaces FastEthernet0/2 switchport
```

#### 🟠 QUARANTINE (move to VLAN 70)
```ios
interface FastEthernet0/2
 description PC-RES2 [QUARANTINE]
 switchport access vlan 70
end
write memory
show interfaces FastEthernet0/2 switchport
```

#### 🟢 RESTORE (return to VLAN 30)
```ios
interface FastEthernet0/2
 description PC-RES2
 switchport access vlan 30
end
write memory
show interfaces FastEthernet0/2 switchport
```

---

## Batch Operations (Multiple Devices Simultaneously)

### Restrict all STUDENTS (PC-STU1 + PC-STU2) — on ACCESS-SW-A
```ios
interface FastEthernet0/1
 switchport access vlan 60
interface FastEthernet0/2
 switchport access vlan 60
end
write memory
show vlan brief
```

### Quarantine all RESEARCH (PC-RES1 + PC-RES2) — on ACCESS-SW-B
```ios
interface FastEthernet0/1
 switchport access vlan 70
interface FastEthernet0/2
 switchport access vlan 70
end
write memory
show vlan brief
```

### Restore all STUDENTS (PC-STU1 + PC-STU2) — on ACCESS-SW-A
```ios
interface FastEthernet0/1
 switchport access vlan 10
interface FastEthernet0/2
 switchport access vlan 10
end
write memory
show vlan brief
```

### Restore all FACULTY (PC-FAC1 + PC-FAC2) — on ACCESS-SW-A
```ios
interface FastEthernet0/3
 switchport access vlan 20
interface FastEthernet0/4
 switchport access vlan 20
end
write memory
show vlan brief
```

### Restore all RESEARCH (PC-RES1 + PC-RES2) — on ACCESS-SW-B
```ios
interface FastEthernet0/1
 switchport access vlan 30
interface FastEthernet0/2
 switchport access vlan 30
end
write memory
show vlan brief
```

---

## Post-Action Verification Commands

### On the switch (after SSH):
```ios
! Check a specific port's VLAN assignment
show interfaces FastEthernet0/1 switchport

! Check all ports and their VLAN assignments
show interfaces status

! Show all VLANs and their active ports
show vlan brief

! Confirm MAC address table reflects new VLAN
show mac address-table vlan 60
show mac address-table vlan 70
```

### On the affected PC (Desktop → Command Prompt):
```
ipconfig /release
ipconfig /renew
ipconfig
! Verify address is in 192.168.60.x (restricted) or 192.168.70.x (quarantine)
! Or home subnet when restored

ping 192.168.50.13    ! SRV-REMEDIATE — should reach in both restricted & quarantine
ping 192.168.50.10    ! SRV-RESEARCH  — should FAIL in restricted & quarantine
ping 8.8.8.8          ! Internet      — should PASS only in restricted
```

---

## Quick Reference Summary Table

| Device | Switch | Port | Home VLAN | Restrict VLAN | Quarantine VLAN |
|--------|--------|------|-----------|---------------|-----------------|
| PC-STU1 | ACCESS-SW-A | Fa0/1 | 10 | 60 | 70 |
| PC-STU2 | ACCESS-SW-A | Fa0/2 | 10 | 60 | 70 |
| PC-FAC1 | ACCESS-SW-A | Fa0/3 | 20 | 60 | 70 |
| PC-FAC2 | ACCESS-SW-A | Fa0/4 | 20 | 60 | 70 |
| PC-ADM1 | ACCESS-SW-A | Fa0/5 | 40 | 60 | 70 |
| PC-ADM2 | ACCESS-SW-A | Fa0/6 | 40 | 60 | 70 |
| PC-RES1 | ACCESS-SW-B | Fa0/1 | 30 | 60 | 70 |
| PC-RES2 | ACCESS-SW-B | Fa0/2 | 30 | 60 | 70 |

---

*Document end — `configs/containment_commands.md`*
