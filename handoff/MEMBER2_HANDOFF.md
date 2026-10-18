# Handoff Package for Member 2: ACLs & Traffic Filtering

## 1. Network Baseline Summary
- **Baseline Project File:** `CN_Baseline_v1.pkt`
- **Topology:** Single-path core-in-the-middle architecture.
- **Switching & Routing:** Layer 2 VLANs, 802.1Q trunks, Layer 3 SVIs on CORE-SW with `ip routing` active.
- **Internet Gateway & NAT:** CORE-SW Fa0/24 (10.0.0.1/30) $\leftrightarrow$ EDGE-R Gi0/0 (10.0.0.2/30). EDGE-R Gi0/1 (203.0.113.1/30) $\leftrightarrow$ INTERNET-SRV (203.0.113.2/30).
- **Credentials:** Username `admin` (privilege 15), password `<LAB_PASSWORD>`, SSH version 2 on all switches.

## 2. Critical Constraints for Member 2
1. **ACL Placement:** All ACLs MUST be applied **inbound (`ip access-group <ACL> in`) on the CORE-SW SVIs only** (`interface Vlan10`, `Vlan20`, `Vlan30`, etc.).
2. **Internet Traffic Path:** The internet path is strictly `CORE-SW Fa0/24` $\rightarrow$ `EDGE-R` $\rightarrow$ `INTERNET-SRV`. Do not block this path or the 10.0.0.0/30 transit subnet.
3. **EDGE-R Access List:** `access-list 1` on `EDGE-R` is **strictly for NAT overload** (`ip nat inside source list 1 interface Gi0/1 overload`). Do NOT modify or use it for security filtering.
4. **Management Access Protection:** `POLICY-HOST` (`192.168.40.50`) must ALWAYS be permitted to reach switch management IPs (`192.168.40.1`, `192.168.40.21`, `192.168.40.22`) on TCP port 22 (SSH).
5. **DHCP Preservation:** DHCP requests (UDP ports 67/68) must continue to function across all VLANs without interruption.

## 3. Reference Tables
### VLAN Allocation
| VLAN | Name | Subnet | Gateway (CORE-SW SVI) | Role |
|---|---|---|---|---|
| 10 | STUDENTS | 192.168.10.0/24 | 192.168.10.1 | Student client hosts |
| 20 | FACULTY | 192.168.20.0/24 | 192.168.20.1 | Faculty client hosts |
| 30 | RESEARCH | 192.168.30.0/24 | 192.168.30.1 | Research client hosts |
| 40 | ADMIN | 192.168.40.0/24 | 192.168.40.1 | Admin hosts & Switch Mgmt |
| 50 | SERVERS | 192.168.50.0/24 | 192.168.50.1 | Internal servers |
| 60 | RESTRICTED | 192.168.60.0/24 | 192.168.60.1 | Remediation/Restricted |
| 70 | QUARANTINE | 192.168.70.0/24 | 192.168.70.1 | Isolated quarantine |
| 999 | BLACKHOLE | None | None | Native VLAN & Unused ports |

### Internal Servers (VLAN 50)
- `SRV-RESEARCH`: 192.168.50.10 (HTTP, HTTPS)
- `SRV-DB`: 192.168.50.11 (FTP)
- `SRV-ADMIN`: 192.168.50.12 (HTTP, HTTPS)
- `SRV-REMEDIATE`: 192.168.50.13 (HTTP, DNS)
