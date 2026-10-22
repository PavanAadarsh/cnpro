# Packet Tracer implementation

Open `University_Research_Network_Final.pkt` in Cisco Packet Tracer 9.0.1. This is the user-built, GUI-tested project. The older `.pkt` files are checkpoints; the filename alone is not a completion claim.

## Authoritative configuration

Use the seven `evidence/*_final_running_config.txt` exports for the actual device configuration. They were exported through Packet Tracer and inspected locally on 2026-10-22. `evidence/PT_VERIFICATION_REPORT.md` records outstanding items.

Locally preserved `topology.json`, `cabling.csv`, `configs/`, `candidate-configs/`, `stateful-configs/`, `stateful_design.json`, `prepare_package.py`, `native_helpers.js`, and the original 136-case matrix describe earlier candidates. They do **not** reproduce this final physical-interface design and are intentionally excluded from the published final package, along with older topology checkpoints. Do not import or run them over the working topology. The scripting API was not used to control this implementation.

## Current reproducible handoff and offline checks

`final_package/` describes the actual 21-device, 27-link design, including endpoint
addresses, final cabling and references to the seven genuine exports. Generate it
without opening or controlling Packet Tracer:

```powershell
python -B packet_tracer/build_final_package.py
python -B -m unittest discover -s packet_tracer/tests -p test_final_package.py -v
python -B packet_tracer/verify_handoff.py
```

Run these from the repository root. The builder checks cabled switch-port modes,
VLANs, trunk membership and shutdown state against the exports. It writes a new
136-case acceptance matrix and detailed initial-flow ACL/routing/zone-policy
audit. This matrix is distinct from the earlier candidate matrix. The results
are configuration inferences, not new network test passes; return paths, NAT,
services, negotiated FTP data and automatic recovery are outside its model.
Existing live observations remain in `evidence/observed_test_results.csv`.

The current exports match 135 of those 136 policy expectations. Quarantine's own
gateway ping is blocked, contrary to the detailed policy in
`monitoring_integration/POLICY_RESOLUTION.md`. Consequently the builder exits 1
after writing its reports; this is a reported pending correction, not a build
crash. Fifteen focused software tests pass, including detection of this gap and
an offline check of the pending correction in temporary configuration copies.

`final_package/pending_changes/EDGE-R_quarantine_gateway.cfg` prepares a new ACL
with DHCP, only the agreed gateway-echo exception, and a final deny. The rollback
file restores the original binding. Neither is applied to the `.pkt` or genuine
exports. After manual application, verify gateway ping and continued server
denial, save the router/topology, re-export EDGE-R, and rebuild the package.
The script never generates a topology binary or sets up endpoint services.

`verify_handoff.py` is read-only: it checks packaged file hashes and compares the
generated topology, cabling, audit and pending correction with current sources.
It reports configuration gaps separately. A successful integrity check does not
mean every policy expectation or live simulator test passed. After intentional
edits, review and refresh the artifact manifest rather than treating a changed
hash as evidence of a successful network test.

## Implemented topology

CORE-SW aggregates VLANs at Layer 2. Its Gi0/1 and Gi0/2 trunks connect ACCESS-SW-A and ACCESS-SW-B; native VLAN 999 is unused for endpoint traffic. All endpoint subnets are /24 with gateway .1.

| VLAN | Role | Gateway device/interface | CORE access port |
|---|---|---|---|
| 10 | Students | FW-STU-FAC Gi0/0, 192.168.10.1 | Fa0/1 |
| 20 | Faculty | FW-STU-FAC Gi0/1, 192.168.20.1 | Fa0/2 |
| 30 | Research | FW-RES-ADM Gi0/0, 192.168.30.1 | Fa0/4 |
| 40 | Administration | FW-RES-ADM Gi0/1, 192.168.40.1 | Fa0/5 |
| 50 | Servers | FW-SRV-REST Gi0/0, 192.168.50.1 | Fa0/7 |
| 60 | Restricted | FW-SRV-REST Gi0/1, 192.168.60.1 | Fa0/8 |
| 70 | Quarantine | EDGE-R Gi0/2, 192.168.70.1 | Fa0/10 |
| 900 | Firewall transit | 10.255.0.0/29 | Fa0/3,6,9,24 |

Transit addresses: EDGE-R .1 (Gi0/0), FW-STU-FAC .2, FW-RES-ADM .3, FW-SRV-REST .4 (each firewall Gi0/2). EDGE-R Gi0/1 is 203.0.113.1/30, connected to INTERNET-SRV 203.0.113.2/30. Static routes are in the exports. Only user subnets 10/20/30/40 participate in PAT.

ACCESS-SW-A Fa0/1-2: students; Fa0/3-4: faculty; Fa0/5-6: administration; Fa0/7: POLICY-HOST. ACCESS-SW-B Fa0/1-2: researchers; Fa0/3: research server; Fa0/4: DB server; Fa0/5: admin server; Fa0/6: remediation server. Endpoint NICs use FastEthernet0. Access-switch Gi0/1 ports are the uplinks.

## Endpoints and services

Normal user PCs use DHCP, DNS 203.0.113.2. POLICY-HOST is static 192.168.40.50/24, gateway 192.168.40.1, DNS 203.0.113.2. Restricted and Quarantine DHCP advertise DNS 192.168.50.13; Quarantine ACLs block DNS use.

| Server | Address | Required service |
|---|---|---|
| SRV-RESEARCH | 192.168.50.10 | HTTP and PT HTTPS |
| SRV-DB | 192.168.50.11 | Authenticated FTP, Read/List account |
| SRV-ADMIN | 192.168.50.12 | HTTP and PT HTTPS |
| SRV-REMEDIATE | 192.168.50.13 | HTTP and DNS A record srv-remediate |
| INTERNET-SRV | 203.0.113.2/30 | HTTP, PT HTTPS, DNS |

Internal servers use gateway 192.168.50.1; INTERNET-SRV uses gateway 203.0.113.1. External DNS records are www.example.com and srv-research/db/admin/remediate at their addresses above. The FTP account is researchlab with a locally chosen lab-only password; obtain it from the project owner. Do not put the password in documentation, screenshots, or source. Packet Tracer stores the configured account in the topology; the `.pkt` should be treated as containing that lab credential.

## Run and demonstrate

1. Open the final `.pkt`, choose Realtime, and allow links/STP to settle. Do not apply the older candidate scripts. The router securityk9 packages were enabled and verified in the simulator.
2. Use each PC's Desktop applications. Examples: Student `http://srv-research` allowed and `https://srv-research` denied; Faculty HTTPS allowed; Admin `http://srv-admin` allowed. Admin may initiate diagnostics to normal user roles; the reverse initiation is denied.
3. Research/Admin FTP: `ftp srv-db`, enter the lab account interactively, then `passive` until Off, followed by `dir`. Active-mode listing was verified. The data rule explicitly allows only SRV-DB source TCP 20 to Research/Admin destination ports >1023. It is a static exception, not a negotiated authenticated-session-only pinhole. Passive-mode listing remains unresolved. File get/put/delete/rename behaviour has not been verified.
4. Manual adaptive demonstration on ACCESS-SW-A: `enable`, `configure terminal`, `interface FastEthernet0/2`, `switchport access vlan 60` (Restricted), `70` (Quarantine), or `10` (Recovery to NORMAL), then `end`. On PC-STU2 select Static then DHCP to renew. Restricted permits remediation HTTP/DNS; Quarantine permits DHCP requests but blocks ordinary routed IP traffic. Restore VLAN 10 and DHCP before saving the normal submission state.
5. Verify VLAN readback with `show vlan brief`, endpoint address through IP Configuration, and actual application connectivity. Do not count an unknown readback as recovery success. Final exported Fa0/2 is VLAN 10; the recovery screenshots show a normal lease and restored research HTTP.
6. Useful displays: `show ip route`, `show zone security`, `show zone-pair security`, `show policy-map type inspect zone-pair sessions`, `show ip nat translations`. Bare `show policy-map type inspect zone-pair` and `terminal length 0` were not supported in this simulator.
7. After intentional configuration changes, `write memory` on the affected device and Ctrl+S on the topology. Config > GLOBAL > Settings > Running Config > Export produces the configuration backups.

## Important boundaries

Zone membership was rejected on EDGE-R subinterfaces, so three additional physical-interface firewall routers were used. NAT and ZBF together on EDGE-R produced a demonstrated zone-pair lookup failure. EDGE-R therefore does routing/PAT; normal role policy enforcement remains on the three firewall routers. EDGE-R Gi0/2 retains Quarantine zone membership and its DHCP-only inbound ACL. Unused old EDGE-R zone pairs/ACLs remain in the export; they are not the active Internet enforcement path.

These are Packet Tracer GUI observations, not Linux packet captures or production Cisco deployment. No automatic Python-to-PT control, automatic detection, or timed recovery has been demonstrated. Full 30/120-minute recovery expiry remains pending requirement clarification. PT HTTPS page display does not verify real TLS cryptography. The original 136-case matrix has not been completely run, and no PT timing/throughput comparison or full policy coverage is claimed. Existing Linux implementation and evidence remain separate.
