# Phase 7: End Devices Addressing and Services

## 1. Static Hosts & Servers Configuration
All Subnet Masks: `255.255.255.0`
DNS Server for all: `203.0.113.2`

| Device | IP Address | Subnet Mask | Default Gateway | DNS Server | Services to Enable |
|---|---|---|---|---|---|
| INTERNET-SRV | 203.0.113.2 | 255.255.255.252 | 203.0.113.1 | 203.0.113.2 | HTTP: ON, DNS: ON (A record: `www.example.com` -> `203.0.113.2`) |
| SRV-RESEARCH | 192.168.50.10 | 255.255.255.0 | 192.168.50.1 | 203.0.113.2 | HTTP: ON, HTTPS: ON |
| SRV-DB | 192.168.50.11 | 255.255.255.0 | 192.168.50.1 | 203.0.113.2 | FTP: ON (Port 21 stand-in for MySQL 3306) |
| SRV-ADMIN | 192.168.50.12 | 255.255.255.0 | 192.168.50.1 | 203.0.113.2 | HTTP: ON, HTTPS: ON |
| SRV-REMEDIATE | 192.168.50.13 | 255.255.255.0 | 192.168.50.1 | 203.0.113.2 | HTTP: ON, DNS: ON |
| POLICY-HOST | 192.168.40.50 | 255.255.255.0 | 192.168.40.1 | 203.0.113.2 | None (Member 3 Policy/SSH Enforcement Workstation) |

## 2. DHCP Client PCs
All set to **DHCP** under Desktop -> IP Configuration:
| PC Name | Switch Port | VLAN | Expected Subnet | Expected IP Range | Expected Gateway |
|---|---|---|---|---|---|
| PC-STU1 | ACCESS-SW-A Fa0/1 | 10 | 192.168.10.0/24 | 192.168.10.100 - .254 | 192.168.10.1 |
| PC-STU2 | ACCESS-SW-A Fa0/2 | 10 | 192.168.10.0/24 | 192.168.10.100 - .254 | 192.168.10.1 |
| PC-FAC1 | ACCESS-SW-A Fa0/3 | 20 | 192.168.20.0/24 | 192.168.20.100 - .254 | 192.168.20.1 |
| PC-FAC2 | ACCESS-SW-A Fa0/4 | 20 | 192.168.20.0/24 | 192.168.20.100 - .254 | 192.168.20.1 |
| PC-ADM1 | ACCESS-SW-A Fa0/5 | 40 | 192.168.40.0/24 | 192.168.40.100 - .254 | 192.168.40.1 |
| PC-ADM2 | ACCESS-SW-A Fa0/6 | 40 | 192.168.40.0/24 | 192.168.40.100 - .254 | 192.168.40.1 |
| PC-RES1 | ACCESS-SW-B Fa0/1 | 30 | 192.168.30.0/24 | 192.168.30.100 - .254 | 192.168.30.1 |
| PC-RES2 | ACCESS-SW-B Fa0/2 | 30 | 192.168.30.0/24 | 192.168.30.100 - .254 | 192.168.30.1 |
