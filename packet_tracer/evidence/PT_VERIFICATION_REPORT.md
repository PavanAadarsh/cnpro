# Packet Tracer verification record — 2026-10-22

## Basis and status

The user built and operated Packet Tracer 9.0.1 while the assistant reviewed screenshots and CLI output. This report records those observations; the assistant did not independently rerun GUI tests. Seven genuine running-config exports were read on disk. `University_Research_Network_Final.pkt` exists (158923 bytes after the CORE finishing update); its binary contents were not independently decoded or reopened by the assistant.

See `observed_test_results.csv` and `screenshots/`. Quarantine remediation denial was reported by the user in text rather than supplied as a screenshot. No measurements or timestamps have been fabricated. Simulator latency displays are not physical-network benchmarks. There is no claim that all 136 planned cases passed.

## Verified observations

- Student, Faculty, Research and Administration DHCP leases had the expected subnet, gateway and DNS. The second PCs and POLICY-HOST settings were shown later.
- Student/Faculty own-gateway pings passed; cross-role initiation was denied in both directions.
- Admin initiated successful diagnostics to Research, Student and Faculty, including their echo replies. Initial losses and successful repeats are retained in the evidence. Student and Research reverse initiation to Admin was denied.
- Student external HTTP by IP and hostname worked after the NAT/ZBF separation. A PAT entry showed 192.168.10.100 translated to 203.0.113.1. Student external ICMP and Restricted external HTTP were denied.
- Research HTTP by hostname was allowed to Student. Research HTTPS was denied to Student and allowed to Faculty. Admin HTTP was denied to Faculty and allowed to Admin.
- Restricted PC-STU2 obtained 192.168.60.100 and remediation DNS, loaded remediation HTTP by hostname, and failed remediation ping, research HTTP and DB FTP connection.
- PC-STU2 obtained 192.168.70.100 in Quarantine. The user reported remediation HTTP timeout. On recovery it obtained 192.168.10.101 with normal DNS and loaded the research portal. Final ACCESS-SW-A export places Fa0/2 back in VLAN 10.
- FTP correct login/listing and incorrect-login rejection were observed locally in the Server VLAN. Research and Admin active-mode directory listings later passed across their firewall paths using the explicit TCP-20 data exception. Passive directory listing timed out and remains unresolved.

## Export review

All seven expected exports exist. Inspected addresses, role zones, routes, DHCP pools, access-port assignments, Quarantine ACL and normal-user-only NAT agree with the manual build. No configured username/password, enable secret, SNMP community or private-key block was found in a targeted scan of those seven text files. This does not certify the topology binary or unrelated files credential-free; the simulated FTP password is stored in the topology and was not printed in this report.

The CORE finishing update was subsequently applied by the user and verified in the re-exported file: Fa0/11-23 are shutdown access ports in VLAN 999; Vlan1 is shutdown; Vlan40 has 192.168.40.2/24 and is not shutdown; the default gateway is 192.168.40.1; VTY 0-4 has `transport input none`. All seven exports now disable remote VTY transport. Live management-SVI connectivity was not tested. The user also reported applying `no ip routing`; its absence from the export is not independent proof of runtime forwarding state.

## Remaining work and limits

1. The CORE finishing block, re-export and final topology save are complete. No successful live verification of the management SVI is claimed; verify its reachability if it is a required acceptance case.
2. Only an observed subset of access cases has been run. In particular, missing role/service combinations and server-initiated-denial coverage must not be labelled passed based on configuration alone. FTP file retrieval and denied write/delete/rename commands remain unverified; the account's RL configuration alone is not behavioural proof.
3. No automatic PT detection/controller integration, timed recovery, or PT static/adaptive benchmark has been demonstrated. Transitions were controlled manual CLI changes with real simulated VLAN/DHCP/connectivity changes. Full 30/120-minute expiry is pending clarification, not failed or completed.
4. The active FTP data exception authorizes TCP source port 20 from SRV-DB to Research/Admin high ports, including outside an authenticated FTP session. It is a documented lab policy exception, not equivalent to a dynamically negotiated pinhole. Passive FTP and real TLS properties remain limitations.
5. Default/unused server services have not been fully inventoried or disabled. VTY/SSH controller management was deliberately disabled rather than claimed operational. Earlier candidate topology/configuration files are preserved but superseded by the actual exports and README; do not replay them over the final topology.
6. Clean up obsolete inactive EDGE-R configuration only if needed for presentation; it is not used for the verified Internet policy. CORE Fa0/24 retains inert trunk settings while configured in access mode.

Current verdict: core demonstration substantially verified; full project completion is not claimed. This records the preceding local Packet Tracer verification; subsequent user-authorized branch publication is separate. The original cnpro-member4 folder and Linux files were not edited during that Packet Tracer verification.
