# Handoff Package for Member 3: Policy Engine & Dynamic Containment

## 1. Containment Design Principle
Enforcement is achieved by **physical/logical port VLAN re-assignment**, NOT by modifying ARP tables or host OS networking stacks. ARP maintains standard, unmodified OS behavior. When a host misbehaves, the Policy Engine simply pushes an automated configuration change to the switchport hosting the offender.

## 2. Port-to-Device Mapping
| Switch | Port | Device Attached | Normal VLAN | MAC / IP Assignment |
|---|---|---|---|---|
| **ACCESS-SW-A** | Fa0/1 | PC-STU1 | VLAN 10 | DHCP (192.168.10.100+) |
| **ACCESS-SW-A** | Fa0/2 | PC-STU2 | VLAN 10 | DHCP (192.168.10.100+) |
| **ACCESS-SW-A** | Fa0/3 | PC-FAC1 | VLAN 20 | DHCP (192.168.20.100+) |
| **ACCESS-SW-A** | Fa0/4 | PC-FAC2 | VLAN 20 | DHCP (192.168.20.101+) |
| **ACCESS-SW-A** | Fa0/5 | PC-ADM1 | VLAN 40 | DHCP (192.168.40.100+) |
| **ACCESS-SW-A** | Fa0/6 | PC-ADM2 | VLAN 40 | DHCP (192.168.40.101+) |
| **ACCESS-SW-A** | Fa0/7 | POLICY-HOST | VLAN 40 | Static: 192.168.40.50 |
| **ACCESS-SW-B** | Fa0/1 | PC-RES1 | VLAN 30 | DHCP (192.168.30.100+) |
| **ACCESS-SW-B** | Fa0/2 | PC-RES2 | VLAN 30 | DHCP (192.168.30.101+) |

## 3. Dynamic Containment Command Syntax
To move an offender into **Restricted VLAN 60** or **Quarantine VLAN 70**, the policy script issues:

```text
configure terminal
interface <target-interface>
 switchport access vlan <60|70>
end
```

### Example: Quarantine PC-STU2 on ACCESS-SW-A
```text
configure terminal
interface FastEthernet0/2
 switchport access vlan 70
end
```

### Reversion: Restoring back to normal
```text
configure terminal
interface FastEthernet0/2
 switchport access vlan 10
end
```
*(Once moved, the client device issues a DHCP renew or receives a DHCP lease in the 192.168.60.0/24 or 192.168.70.0/24 subnet).*
