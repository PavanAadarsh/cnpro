# Phase 8: Verification Test Matrix (Baseline - No ACLs)

| Test ID | Test Description | Device / Source | Command / Action | Expected Result | Pass / Fail |
|---|---|---|---|---|---|
| **T1** | VLAN & Port Verification | All 3 switches | `show vlan brief` | VLANs 10–70 and 999 exist; port allocations match Section 4.5 | |
| **T2** | Trunking Verification | CORE-SW | `show interfaces trunk` | Gi0/1 and Gi0/2 trunking; native 999; allowed 10,20,30,40,50,60,70 | |
| **T3** | Core Interfaces Status | CORE-SW | `show ip interface brief` | Vlan10–70 up/up (.1 IPs); Fa0/24 up/up (10.0.0.1) | |
| **T4** | Core Routing Table | CORE-SW | `show ip route` | Connected routes for 7 VLAN subnets + 10.0.0.0/30; default route `S* 0.0.0.0/0 via 10.0.0.2` | |
| **T5** | Edge Router Routing Table | EDGE-R | `show ip route` | Connected routes for 10.0.0.0/30 & 203.0.113.0/30; static route `192.168.0.0/16 via 10.0.0.1` | |
| **T6** | DHCP Leases Binding | CORE-SW | `show ip dhcp binding` | 8 client leases present, each in its own subnet's .100+ range | |
| **T7** | Gateway Reachability | Each PC | `ping <VLAN-gateway-IP>` | All 8 PCs successfully ping their own default gateway | |
| **T8** | Inter-VLAN Routing & Server Connectivity | Each PC | `ping <target-PC/server-IP>` | All inter-VLAN pairs and 4 internal servers reachable (baseline permits all) | |
| **T9** | Internet Access & DNS Resolution | PC-STU1 | `ping 203.0.113.2`, `ping www.example.com`, Web Browser `http://www.example.com` | Pings succeed and example web page loads | |
| **T10** | NAT Translations Verification | EDGE-R | `show ip nat translations` | NAT table shows translated sessions for internal hosts (192.168.x.x -> 203.0.113.1) | |
| **T11** | Switch Management SSH | POLICY-HOST | `ssh -l admin 192.168.40.1`, `192.168.40.21`, `192.168.40.22` | Password prompt `<LAB_PASSWORD>`, successful login | |
| **T12** | VLAN 60 Move Test | ACCESS-SW-A & PC-STU2 | `int Fa0/2` -> `switchport access vlan 60`; Command Prompt: `ipconfig /renew` | PC-STU2 leases 192.168.60.100+; pings 192.168.60.1 | |
| **T13** | VLAN 70 Move Test | ACCESS-SW-A & PC-STU2 | `int Fa0/2` -> `switchport access vlan 70`; Command Prompt: `ipconfig /renew` | PC-STU2 leases 192.168.70.100+; pings 192.168.70.1 | |
| **T14** | Revert Move Test | ACCESS-SW-A & PC-STU2 | `int Fa0/2` -> `switchport access vlan 10`; Command Prompt: `ipconfig /renew` | PC-STU2 leases 192.168.10.100+ again | |
| **T15** | Startup Config Persistence | All 4 devices | `show startup-config` | Configurations successfully saved to NVRAM | |
