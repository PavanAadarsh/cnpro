# Phase 1: Physical Topology & Cabling Specification

## 1. Device Inventory (Section 4.1)
| Name | Model | Role |
|---|---|---|
| CORE-SW | Switch 3560-24PS | Layer-3 core, SVIs, DHCP server |
| ACCESS-SW-A | Switch 2960-24TT | Access layer |
| ACCESS-SW-B | Switch 2960-24TT | Access layer |
| EDGE-R | Router 2911 | Gateway to simulated internet, NAT |
| INTERNET-SRV | Server-PT | Simulated internet web + DNS server |
| SRV-RESEARCH | Server-PT | Internal research server |
| SRV-DB | Server-PT | Internal database server (FTP stand-in) |
| SRV-ADMIN | Server-PT | Internal admin server |
| SRV-REMEDIATE | Server-PT | Internal remediation server |
| PC-STU1 | PC-PT | Student Client 1 |
| PC-STU2 | PC-PT | Student Client 2 |
| PC-FAC1 | PC-PT | Faculty Client 1 |
| PC-FAC2 | PC-PT | Faculty Client 2 |
| PC-ADM1 | PC-ADM2 | Admin Client 1 |
| PC-ADM2 | PC-PT | Admin Client 2 |
| PC-RES1 | PC-PT | Research Client 1 |
| PC-RES2 | PC-PT | Research Client 2 |
| POLICY-HOST | PC-PT | Policy host (Member 3) |

## 2. Cabling Plan (Section 4.4)
| From | To | Cable Type |
|---|---|---|
| CORE-SW Gi0/1 | ACCESS-SW-A Gi0/1 | Copper cross-over |
| CORE-SW Gi0/2 | ACCESS-SW-B Gi0/1 | Copper cross-over |
| CORE-SW Fa0/24 | EDGE-R Gi0/0 | Copper straight-through |
| EDGE-R Gi0/1 | INTERNET-SRV Fa0 | Copper cross-over |
| ACCESS-SW-A Fa0/1 | PC-STU1 Fa0 | Straight-through |
| ACCESS-SW-A Fa0/2 | PC-STU2 Fa0 | Straight-through |
| ACCESS-SW-A Fa0/3 | PC-FAC1 Fa0 | Straight-through |
| ACCESS-SW-A Fa0/4 | PC-FAC2 Fa0 | Straight-through |
| ACCESS-SW-A Fa0/5 | PC-ADM1 Fa0 | Straight-through |
| ACCESS-SW-A Fa0/6 | PC-ADM2 Fa0 | Straight-through |
| ACCESS-SW-A Fa0/7 | POLICY-HOST Fa0 | Straight-through |
| ACCESS-SW-B Fa0/1 | PC-RES1 Fa0 | Straight-through |
| ACCESS-SW-B Fa0/2 | PC-RES2 Fa0 | Straight-through |
| ACCESS-SW-B Fa0/3 | SRV-RESEARCH Fa0 | Straight-through |
| ACCESS-SW-B Fa0/4 | SRV-DB Fa0 | Straight-through |
| ACCESS-SW-B Fa0/5 | SRV-ADMIN Fa0 | Straight-through |
| ACCESS-SW-B Fa0/6 | SRV-REMEDIATE Fa0 | Straight-through |
