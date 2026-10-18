# Handoff Package for Member 4: Measurements & Performance Analysis

## 1. Designated Packet Capture Points
For performance evaluation, baseline metrics, latency analysis, and security verification, packets must be captured at the following designated interfaces on `CORE-SW`:

| Capture Interface | Segment / Link | Traffic Type Observed |
|---|---|---|
| **CORE-SW GigabitEthernet0/1** | Trunk link to ACCESS-SW-A | All tagged traffic from VLANs 10, 20, 40 (Students, Faculty, Admin, Policy Host) |
| **CORE-SW GigabitEthernet0/2** | Trunk link to ACCESS-SW-B | All tagged traffic from VLANs 30, 50 (Research hosts, Database, Servers) |
| **CORE-SW FastEthernet0/24** | Transit routed link to EDGE-R | External routed traffic, simulated internet requests, DNS lookups, and NAT packets |

## 2. Measurement Baselines (Established in Phase 8)
- **Local Switching Delay:** < 1 ms across trunks with PortFast active on access edge.
- **Inter-VLAN Routing Latency:** 1–3 ms typical inside Packet Tracer simulation.
- **DHCP Leases:** Subnet leases hand out automatically within 1–2 seconds.
- **NAT Sessions:** Dynamic PAT translation verification on `EDGE-R` Gi0/1.
