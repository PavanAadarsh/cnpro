# POLICY-HOST Configuration Guide

**Module:** BACSE203 – Computer Networks Lab  
**Member:** 3 – Adaptive Policy Engine  
**Document:** `configs/POLICY-HOST_configuration.md`

---

## 1. POLICY-HOST Identity

| Parameter | Value |
|-----------|-------|
| Hostname | POLICY-HOST |
| Role | Adaptive Policy Engine control node |
| IP Address | **192.168.40.50** |
| Subnet Mask | 255.255.255.0 (/24) |
| Default Gateway | **192.168.40.1** (CORE-SW SVI VLAN 40) |
| VLAN | **40** (ADMIN) |
| Connected Switch | **ACCESS-SW-A** |
| Switch Port | **FastEthernet0/7** |
| IP Assignment | **Static** (manually set in Packet Tracer) |

---

## 2. Static IP Configuration in Packet Tracer

### 2.1 Steps (Packet Tracer GUI)

1. Click on **POLICY-HOST** in the topology
2. Open **Desktop** tab
3. Click **IP Configuration**
4. Select **Static** radio button
5. Enter the following values:

```
IP Address   :  192.168.40.50
Subnet Mask  :  255.255.255.0
Default Gateway: 192.168.40.1
DNS Server   :  8.8.8.8          (optional, for internet name resolution)
```

6. Close the dialog — settings apply immediately

### 2.2 Verify Static IP (from POLICY-HOST Desktop → Command Prompt)

```
C:\> ipconfig

FastEthernet0
   IP Address......: 192.168.40.50
   Subnet Mask.....: 255.255.255.0
   Default Gateway.: 192.168.40.1
```

---

## 3. Verifying Network Reachability

Run these pings from the POLICY-HOST Command Prompt **before** attempting SSH:

```
ping 192.168.40.1      ! CORE-SW (gateway + SSH target)
ping 192.168.40.21     ! ACCESS-SW-A (SSH target)
ping 192.168.40.22     ! ACCESS-SW-B (SSH target)
```

Expected result: All pings should return replies with 0% loss.

**If pings fail, check:**
- ACCESS-SW-A Fa0/7 is configured as access port for VLAN 40
- Trunk between ACCESS-SW-A and CORE-SW carries VLAN 40
- CORE-SW SVI VLAN 40 (`interface vlan 40`, `ip address 192.168.40.1 255.255.255.0`, `no shutdown`) is up

---

## 4. ACCESS-SW-A Port Configuration for POLICY-HOST

The following configuration must be applied on **ACCESS-SW-A** (by Member 1 baseline or verified by Member 3):

```ios
ACCESS-SW-A# configure terminal

interface FastEthernet0/7
 description POLICY-HOST
 switchport mode access
 switchport access vlan 40
 spanning-tree portfast
 no shutdown
```

**Verify:**
```ios
ACCESS-SW-A# show interfaces FastEthernet0/7 switchport
! Expect:
! Administrative Mode: static access
! Access Mode VLAN: 40 (ADMIN)
```

---

## 5. SSH Connectivity from POLICY-HOST

### 5.1 SSH to CORE-SW

```
C:\> ssh -l admin 192.168.40.1
```

At the password prompt:
```
Password: Admin@123
```

Expected result:
```
CORE-SW>
```

Enter enable mode:
```
CORE-SW> enable
Password: Admin@123
CORE-SW#
```

### 5.2 SSH to ACCESS-SW-A

```
C:\> ssh -l admin 192.168.40.21
Password: Admin@123
```

Expected result:
```
ACCESS-SW-A>
ACCESS-SW-A> enable
Password: Admin@123
ACCESS-SW-A#
```

### 5.3 SSH to ACCESS-SW-B

```
C:\> ssh -l admin 192.168.40.22
Password: Admin@123
```

Expected result:
```
ACCESS-SW-B>
ACCESS-SW-B> enable
Password: Admin@123
ACCESS-SW-B#
```

---

## 6. SSH Prerequisites on Switches (Member 1 Baseline)

Each switch must have the following IOS configuration for SSH access from POLICY-HOST to work:

```ios
! --- CORE-SW / ACCESS-SW-A / ACCESS-SW-B ---

! Step 1: Set hostname and domain name
hostname <SWITCH-NAME>
ip domain-name lab.local

! Step 2: Generate RSA key (if not already done)
crypto key generate rsa modulus 2048

! Step 3: Enable SSHv2
ip ssh version 2
ip ssh authentication-retries 3
ip ssh time-out 60

! Step 4: Create local admin account
username admin privilege 15 secret Admin@123

! Step 5: Create ACL permitting only POLICY-HOST
ip access-list standard SSH-ONLY
 permit host 192.168.40.50
 deny   any log

! Step 6: Apply SSH-only access on VTY lines
line vty 0 4
 transport input ssh
 login local
 access-class SSH-ONLY in
```

> **Note:** This configuration is expected to be in place from Member 1's deliverable. Member 3 does not modify it — only depends on it.

---

## 7. Quick SSH Test Checklist

| Step | Command | Expected Output |
|------|---------|----------------|
| 1. Verify IP | `ipconfig` | `192.168.40.50` |
| 2. Ping gateway | `ping 192.168.40.1` | Reply from 192.168.40.1 |
| 3. Ping ACCESS-SW-A | `ping 192.168.40.21` | Reply from 192.168.40.21 |
| 4. Ping ACCESS-SW-B | `ping 192.168.40.22` | Reply from 192.168.40.22 |
| 5. SSH CORE-SW | `ssh -l admin 192.168.40.1` | `CORE-SW>` prompt |
| 6. SSH ACCESS-SW-A | `ssh -l admin 192.168.40.21` | `ACCESS-SW-A>` prompt |
| 7. SSH ACCESS-SW-B | `ssh -l admin 192.168.40.22` | `ACCESS-SW-B>` prompt |

---

## 8. Troubleshooting SSH Issues

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `Connection refused` | SSH not enabled on switch | Run `crypto key generate rsa modulus 2048` and `ip ssh version 2` on switch |
| `Connection timed out` | Firewall / ACL blocking | Verify `access-class SSH-ONLY` permits 192.168.40.50 |
| `Authentication failed` | Wrong password or username | Use `username admin privilege 15 secret Admin@123` |
| `No route to host` | VLAN 40 SVI or trunk issue | Check `show ip interface brief` on CORE-SW for VLAN 40 SVI state |
| Password prompt appears but connection drops | `transport input` not set to `ssh` | Set `transport input ssh` on VTY lines |

---

*Document end — `configs/POLICY-HOST_configuration.md`*
