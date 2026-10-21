# Member 3: Adaptive Policy Engine — Complete Execution, Event-Logging Contract & Reconciliation Specification

**BACSE203 – Computer Networks Lab Project**  
**Role:** Member 3 (Adaptive Policy Engine)  
**Control Host:** POLICY-HOST (`192.168.40.50`, VLAN 40, `ACCESS-SW-A` port `Fa0/7`)  
**Target Switches:**
- `CORE-SW`: `192.168.40.1` (Cisco Catalyst 3560-24PS; Edge uplink on `Fa0/24`)
- `ACCESS-SW-A`: `192.168.40.21` (Cisco Catalyst 2960-24TT)
- `ACCESS-SW-B`: `192.168.40.22` (Cisco Catalyst 2960-24TT)

---

## 1. Engine-to-Switch Runtime, Launch, Reset & Recovery Procedure

### 1.1 Architecture & Control Flow

The Adaptive Policy Engine runs on **POLICY-HOST** (`192.168.40.50`). Dynamic containment is enforced strictly via **SSH-driven port VLAN reassignment** without modifying Layer-3 ACLs or interfering with host-level ARP/OS network stacks:

```
[ Security Event / Trigger ]
           │
           ▼
[ Policy Controller (policy_engine.py) ]
     ├─ Evaluates Thresholds (threshold_tracker.py)
     ├─ Updates Persistent State (state_manager.py -> state_db.json)
     └─ Initiates SSH Session (ssh_enforcer.py via Paramiko)
           │
     TCP Port 22 (SSHv2)
     Credentials: admin / Admin@123
           │
           ▼
[ Target Access Switch (ACCESS-SW-A / ACCESS-SW-B) ]
     ├─ configure terminal
     ├─ interface <target-port>
     ├─ switchport access vlan <60|70|home_vlan>
     ├─ end
     └─ write memory
           │
           ▼
[ Target Endpoint PC ]
     └─ DHCP renews lease into new subnet (192.168.60.0/24 or 192.168.70.0/24)
```

### 1.2 Runtime Launch & Operational Commands

From the POLICY-HOST terminal (or project directory `cnpro-member3-adaptive-policy`):

| Action | Command | Expected Output / Behavior |
|---|---|---|
| **View Device State Table** | `python simulate_event.py status` | Outputs real-time table of all 8 endpoints, current state, current VLAN, assigned switch/port, violation count, and active containment timestamp. |
| **Inject Security Violation** | `python simulate_event.py event <DEVICE> <EVENT_TYPE>` | Evaluates event against active window; triggers SSH VLAN change if threshold breached; logs state change. |
| **Manual Admin Override** | `python simulate_event.py enforce <DEVICE> <NORMAL\|RESTRICTED\|QUARANTINE>` | Immediately drives target port into specified state over SSH (TH-07). |
| **Run Recovery Sweep** | `python simulate_event.py recover` | Evaluates hold timers (`RESTRICTED`: 30m, `QUARANTINE`: 120m). If criteria met, restores port to home VLAN. |
| **Immediate Manual Reset** | `python simulate_event.py clear <DEVICE>` | Admin clear (REC-01). Instantly restores target endpoint port to original Home VLAN and clears violations. |

### 1.3 Baseline System Reset Procedure

To reset the entire environment back to a clean baseline (all devices in NORMAL state):

1. **Software Engine Reset:**
   ```powershell
   # Restore all devices to NORMAL via engine
   python simulate_event.py clear PC-STU1
   python simulate_event.py clear PC-STU2
   python simulate_event.py clear PC-FAC1
   python simulate_event.py clear PC-FAC2
   python simulate_event.py clear PC-ADM1
   python simulate_event.py clear PC-ADM2
   python simulate_event.py clear PC-RES1
   python simulate_event.py clear PC-RES2
   ```
2. **Switch CLI Direct Verification:**
   ```ios
   ! On ACCESS-SW-A:
   show interfaces status
   ! Verify Fa0/1, Fa0/2 in VLAN 10; Fa0/3, Fa0/4 in VLAN 20; Fa0/5, Fa0/6, Fa0/7 in VLAN 40.

   ! On ACCESS-SW-B:
   show interfaces status
   ! Verify Fa0/1, Fa0/2 in VLAN 30; Fa0/3-Fa0/6 in VLAN 50.
   ```
3. **Client IP Synchronization:**
   On affected PCs (e.g. `PC-STU1` Command Prompt):
   ```cmd
   ipconfig /release
   ipconfig /renew
   ipconfig
   ```

---

## 2. Event-Source / Logging Contract, Timestamps & Clock Model

### 2.1 Event Ingestion Contract

The policy engine implements an explicit logging and event intake schema. Events are ingested into `events_db.json` and evaluated within discrete sliding time windows:

```json
{
  "event_id": "EVT-20261019-001",
  "timestamp": "2026-10-19T12:00:00.000Z",
  "device_name": "PC-STU1",
  "event_type": "auth_failure",
  "source_ip": "192.168.10.100",
  "target_ip": "192.168.50.10",
  "detection_source": "MANUAL_INJECTION"
}
```

#### Valid Event Types & Schema Definitions
- `auth_failure`: Failed authentication attempts (SSH, web portal, or database auth failure). Window: **300 seconds (5 min)**.
- `port_scan`: Probing multiple ports in rapid succession. Window: **600 seconds (10 min)**.
- `cross_vlan_attempt`: Probing or sending packets destined for prohibited user VLANs. Window: **600 seconds (10 min)**.
- `spoofing`: Sending packets with forged source IP/VLAN tags. Window: **600 seconds (10 min)**.
- `policy_violation`: General ACL violation logged by CORE-SW syslog or simulated operator action. Window: **600 seconds (10 min)**.

### 2.2 Dual-Mode Event-Source Model (Simulation vs Production)

To reconcile simulation environments (Cisco Packet Tracer) with live deployments (GNS3 / physical hardware):

1. **In Packet Tracer Simulation (Manual Injection Contract):**
   - Packet Tracer switches do not provide a programmable outbound webhook or REST API.
   - Therefore, security events are explicitly fed via the **Manual Injection Contract** using `simulate_event.py event <DEVICE> <EVENT_TYPE>`.
   - The operator simulates the traffic in Packet Tracer (e.g., initiating failed SSH attempts from `PC-STU1` to `CORE-SW`), then logs/injects the corresponding event into the Policy Controller.
2. **In GNS3 / Physical Rig (Syslog Tail / NetFlow Collector):**
   - Cisco IOS syslog messages (`%SEC-6-IPACCESSLOGP`) generated by `deny ip any any log` on CORE-SW are forwarded via UDP 514 to POLICY-HOST (`192.168.40.50`).
   - The policy engine's background parser extracts the originating IP, resolves the device via the MAC/Port registry, and automatically feeds the event into `handle_event()`.

### 2.3 Clock Information & Synchronization

- **Internal Engine Clock:** Uses standardized **UTC ISO-8601 timestamps** (`datetime.now(timezone.utc).isoformat()`).
- **Network Clock Model:** In lab simulation, relative elapsed delta (`now - event_time`) governs threshold evaluation and hold timers.
- **Clock Drift Mitigation:** When evaluating sliding windows and hold-timer recovery, the engine calculates difference in epoch seconds (`timedelta.total_seconds()`), making the evaluation immune to timezone changes or manual system time shifts.

---

## 3. Reconciled Thresholds, Recovery Behavior & Quarantine Permissions

### 3.1 Consolidated Threshold Matrix

| Threshold ID | Trigger Condition | Sliding Window | Source State | Resulting State | Enforcement Action |
|---|---|---|---|---|---|
| **TH-01** | `auth_failure` count $\ge 3$ | 300 s (5 min) | NORMAL | **RESTRICTED** | Move port to VLAN 60 |
| **TH-02** | `port_scan` count $\ge 1$ | 600 s (10 min) | NORMAL | **RESTRICTED** | Move port to VLAN 60 |
| **TH-03** | Repeat violation while RESTRICTED | 600 s (10 min) | RESTRICTED | **QUARANTINE** | Escalate port to VLAN 70 |
| **TH-04** | Violation while already QUARANTINE | Active window | QUARANTINE | **QUARANTINE** | Logged; hold timer restarts; remains in VLAN 70 |
| **TH-05** | `cross_vlan_attempt` count $\ge 2$ | 600 s (10 min) | NORMAL | **RESTRICTED** | Move port to VLAN 60 |
| **TH-06** | `spoofing` count $\ge 1$ (High Severity) | 600 s (10 min) | NORMAL | **QUARANTINE** | Direct isolation to VLAN 70 |
| **TH-07** | Administrator Manual Enforce | Immediate | Any | **Target State** | Forced push to NORMAL, RESTRICTED, or QUARANTINE |

### 3.2 Reconciled Recovery Logic & Hold Timers

Recovery always restores the device directly to its designated **Home VLAN**:

| Recovery ID | Current State | Target State | Reconciled Hold Period | Prerequisite Conditions | Execution Mechanism |
|---|---|---|---|---|---|
| **REC-01** | RESTRICTED or QUARANTINE | **NORMAL** | Immediate (0 s) | Administrative command / operator clear | `simulate_event.py clear <DEV>` |
| **REC-02** | RESTRICTED | **NORMAL** | **30 minutes** (1,800 s) | Hold timer elapsed **AND** zero violations in last 10 minutes | Automatic via `simulate_event.py recover` |
| **REC-03** | QUARANTINE | **NORMAL** | **120 minutes** (7,200 s) | Hold timer elapsed **AND** zero violations in last 10 minutes | Automatic via `simulate_event.py recover` |
| **REC-04** | QUARANTINE | **NORMAL** | **120 minutes** (Hold timer required) | Hold timer elapsed **AND** Endpoint completes remediation (`remediated=True`, waiving 10m quiet period) | Automatic via `simulate_event.py recover` / background worker |

### 3.3 Reconciled Quarantine & Restricted Permissions Matrix

This access matrix is formally aligned with Member 1's CORE-SW SVI ACLs and Member 2's Security Policy:

| Service / Destination | NORMAL State (VLAN 10/20/30/40) | RESTRICTED State (VLAN 60) | QUARANTINE State (VLAN 70) | Verification Command |
|---|---|---|---|---|
| **DHCP Services** | ✅ Permitted (Local Gateway) | ✅ Permitted (192.168.60.1 pool) | ✅ Permitted (192.168.70.1 pool) | `ipconfig /renew` |
| **Default Gateway ICMP** | ✅ Permitted (Home SVI) | ✅ Permitted (`192.168.60.1`) | ✅ Permitted (`192.168.70.1`) | `ping <gateway_ip>` |
| **Internet Web (TCP 80/443)** | ✅ Permitted | ✅ Permitted (Public only) | ❌ **DENIED** | `ping 203.0.113.2` / Web Browser |
| **Internet DNS (UDP 53)** | ✅ Permitted | ✅ Permitted (`203.0.113.2`) | ❌ **DENIED** | `nslookup domain 203.0.113.2` |
| **SRV-REMEDIATE (192.168.50.13)**| ✅ Permitted | ✅ Permitted (TCP 80, ICMP) | ✅ **PERMITTED** (TCP 80, ICMP) | `ping 192.168.50.13` & HTTP |
| **Internal Servers (192.168.50.10-12)** | Policy-dependent | ❌ **DENIED** | ❌ **DENIED** | `ping 192.168.50.10` (Fails) |
| **Peer User Subnets** | ❌ Denied by Inter-VLAN ACL | ❌ **DENIED** | ❌ **DENIED** | `ping 192.168.20.100` (Fails) |
| **Switch Management (SSH 22)** | ❌ Denied (`access-class`) | ❌ **DENIED** | ❌ **DENIED** | `ssh -l admin 192.168.40.21` (Fails) |

---

## 4. End-to-End Verification Runbook for Member 4

Member 4 can verify Member 3's operational criteria using this 4-step sequence:

```powershell
# Step 1: Ensure initial clean state
python simulate_event.py status

# Step 2: Test Normal -> Restricted -> Quarantine progression on PC-STU1
python simulate_event.py event PC-STU1 auth_failure
python simulate_event.py event PC-STU1 auth_failure
python simulate_event.py event PC-STU1 auth_failure
# Output: PC-STU1 is moved to RESTRICTED (VLAN 60)

python simulate_event.py event PC-STU1 policy_violation
# Output: PC-STU1 is escalated to QUARANTINE (VLAN 70)

# Step 3: Verify isolation
# From PC-STU1 in Packet Tracer:
# ping 192.168.50.13 -> SUCCESS (SRV-REMEDIATE allowed)
# ping 203.0.113.2  -> FAILS (Internet blocked)

# Step 4: Full reset
python simulate_event.py clear PC-STU1
# Output: PC-STU1 restored to NORMAL (VLAN 10)
```
