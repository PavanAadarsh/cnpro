# cnpro - University Research Network (BACSE203 CN Lab)

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
