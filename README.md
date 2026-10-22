# cnpro - University Research Network (BACSE203 CN Lab)

## Final project package

Open the completed manual demonstration topology in Cisco Packet Tracer 9.0.1:
[University_Research_Network_Final.pkt](packet_tracer/University_Research_Network_Final.pkt).
Follow [Packet Tracer instructions](packet_tracer/README.md) and consult the
[verified observations and remaining scope](packet_tracer/evidence/PT_VERIFICATION_REPORT.md).
The package contains seven genuine device configuration exports and 15 selected
screenshots. The broader project is not claimed exhaustively verified: PT
transitions are manual, passive FTP remains unresolved, and timed recovery and
remaining access/permission cases are explicitly identified in that report.

The Linux implementation below is a separate reproduction of the adaptive
engine, real TLS/FTP services, automatic detection and captured experiments.
Selected small historical Linux results are published in
[monitoring_integration/evidence/linux-20261021](monitoring_integration/evidence/linux-20261021/README.md).
Raw captures, runtime credentials, caches and duplicated teammate sources stay local.

Publication validation: all **115 software tests passed** on 22 October 2026,
including real localhost TLS tests, in a fresh run without source changes.
[Current software summary](monitoring_integration/evidence/software-20261022/test_summary.json).
The restricted-environment attempt failed two localhost permission checks;
the rerun with localhost access completed successfully. Existing Linux live and
Packet Tracer observations were reviewed, not rerun during publication.

Member 4's local monitoring tools, scenarios, capture workflow and reproduction
instructions: [monitoring/README.md](monitoring/README.md).
Implementation status and verification: [REPORT_MEMBER4.md](REPORT_MEMBER4.md).

Updated integration with the Member 2 ACLs and Member 3 engine:
[monitoring_integration/README.md](monitoring_integration/README.md).
The earlier report above is historical; current integration status is in
[monitoring_integration/COMPLETION_REPORT.md](monitoring_integration/COMPLETION_REPORT.md).

After cloning, prepare the pinned teammate dependencies and run the tests:

```powershell
python -B monitoring_integration/prepare_upstream.py
python -B monitoring_integration/run.py test
```

Latest local implementation: 21 October 2026. The corrected controller now runs
against a real isolated Linux VLAN/DHCP/firewall lab on this laptop. Source-only
checks and software replay are separate from live experiments and packet captures.
See the current completion report and policy-resolution document for exact results,
reproduction steps and the remaining Cisco/long-duration validation scope.

```powershell
python -B monitoring_integration/run.py live
python -B monitoring_integration/run.py audit
```

Teammate-owned baseline files are preserved. Updated teammate implementations are
materialized from their pinned branch commits rather than duplicated in this branch.
