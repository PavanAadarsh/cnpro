# Member 4 — Monitoring and Evaluation: Local Status Report

Date: 18 October 2026 (Asia/Calcutta).

Local project: `C:\Users\samya\Desktop\CN proj\cnpro-member4`

## Outcome

Implemented and tested the independent monitoring/evaluation tools. Full network
evaluation remains blocked by missing project components; no actual campus traffic,
security isolation, detection, recovery, latency, loss or throughput was measured.
No numerical network comparison or network graph is claimed. Nothing was committed,
pushed, uploaded, forked or submitted as a pull request.

## Architecture and inspected implementation

The complete requested Git branch was cloned locally. Its 19 tracked source files
were inspected: Cisco Packet Tracer configuration snippets and running configs,
topology and end-device tables, verification matrix, report and member handoffs.
The repository has neither the referenced `CN_Baseline_v1.pkt` nor screenshots
claimed in Member 1's report. There is no runnable source, existing test suite,
policy engine, event log, packet capture or collected dataset.

CORE-SW has routing and seven SVIs, DHCP and trunks; EDGE-R has NAT ACL 1 and routes.
No CORE-SW security ACL is applied. Therefore this is an architecture baseline,
not a static-security implementation. VLANs 60/70 are routed: membership is not
proof of denied research/admin access. The handoff documents port reassignment,
but no implemented NORMAL/RESTRICTED/QUARANTINED state machine, event format,
thresholds or automatic recovery. No other member's logic was rewritten.

The monitoring architecture is: explicit Packet Tracer traffic procedures → saved
PDU/CLI/application observations and original logs → normalized evidence-backed
JSON → validated metrics → CSV/JSON summaries, Markdown tables and conditional
SVG charts. Real-interface tshark capture is an optional separate workflow, never
presented as capture of simulated Packet Tracer traffic.

## Files created or modified

- `monitoring/evaluate.py`: repository audit, source hashes, availability records,
  evidence import/archive, metric validation/calculation, trial summaries and charts.
- `monitoring/capture.py`: scoped, bounded tshark capture with configuration/scenario
  metadata, raw errors and packet statistics. Requires a project-only interface.
- `monitoring/scenarios.json`: authorized traffic, protected access, violations,
  transition disruption, recovery and performance scenarios using existing hosts.
- `monitoring/tests/test_evaluate.py`: metric, input, failure, evidence and output tests.
- `monitoring/README.md`: exact procedures, observations schema, metric definitions,
  dependency handoffs, measurement uncertainty and reproduction commands.
- `monitoring/requirements.txt`: Python and optional simulator/capture dependencies.
- `monitoring/test-results.txt`: final functional test transcript.
- `monitoring/results/`: actual repository audit and blocked availability-check outputs.
- `REPORT_MEMBER4.md`: this report. Root `README.md` adds navigation links only.

## Actual results and evidence

| Check | Observed result | Interpretation |
|---|---|---|
| Repository inspection | `.pkt`, engine and security ACLs absent | Full network run blocked |
| Tool discovery | Python 3.14.6 available; tshark/tcpdump/PacketTracer absent from PATH; no matching application directory found in Program Files checks | No packet capture or simulator run performed |
| Calculation/import functional suite | 8 tests passed; final transcript in monitoring/test-results.txt | Tests use explicitly synthetic fixtures; not campus-network measurements |
| Capture command with unavailable interface and missing tshark | Exited 2, `tshark unavailable; no capture performed` | Correct preflight failure; no file presented as capture |
| Availability workflow | 18 blocked rows: six scenarios × three configurations | Null network metrics, not 18 executed traffic trials |

Audit evidence:
`monitoring/results/20261018T102624Z-26207990/audit.json`.
Availability source:
`monitoring/results/20261018T102624Z-46c9c62f/availability.json`.
Processed availability report, CSV/JSON, and summary:
`monitoring/results/20261018T102624Z-46c9c62f/20261018T102625Z-e561ed3d/`.
Availability timestamps describe when readiness was checked, not experiment timing.
All timing and network metrics are null. No graphs are generated without measured
comparators. Tests verify chart generation using temporary synthetic fixtures only.

The first test run encountered sandbox restrictions on the system temporary
directory (two errors). Tests were changed to use isolated temporary directories
inside the project; the final rerun passes. No network test failure or success
can be inferred from these software tests. No preexisting automated tests existed.

## Reproduction and measurement definitions

From the local project root:

```
python -m unittest discover -s monitoring/tests -v
python monitoring/evaluate.py audit
python monitoring/evaluate.py blocked
```

Once the real topology, ACLs and engine are supplied, follow monitoring/README.md
and scenarios.json. Collect equal trials under architecture_baseline, static ACLs,
and adaptive with those same ACLs. Preserve separate run folders, source addresses,
configuration snapshots, actual engine logs and service-probe results.
Normalize the observations, then run:

```
python monitoring/evaluate.py analyze --input monitoring/observations.json
```

Detection starts at the defined condition and ends at actual detection. Policy
response starts at detection and ends at the first service denial attributable to
policy. Recovery starts at the documented recovery condition and ends at restored
permitted service. RTT uses successful ICMP samples; loss uses sent/replied counts;
application success and transition disruption use verified request counters.
Goodput requires delivered application bytes and duration. Units, sample counts,
null handling, clock-domain requirements, cadence uncertainty and limitations are
defined in monitoring/README.md. The analysis computes per-trial mean/median/min/max
grouped by scenario and configuration; failed/incomplete trials remain visible but
are excluded from aggregates. Regenerate analysis from saved input and original
evidence, retaining the copied evidence manifest for provenance.

## Completed, partial and blocked work

Completed: source inventory, compatible traffic procedures, metric collection
schema and evidence import, calculation/analysis scripts, raw audit/availability
datasets, scoped capture workflow, documentation and functional software tests.

Partial: packet capture automation is implemented but cannot be exercised against
a project interface here. Scenarios and comparison analysis are ready for real
observations, but no live campus result exists. No substitute mock network was built.

Blocked: restore/build and run Packet Tracer topology; Member 2's access matrix and
SVI ACLs; Member 3's executable deterministic engine, logging, thresholds, recovery
and effective enforcement; synchronized event/probe evidence. Genuine security and
performance comparison, network plots and full adaptive verification depend on
these inputs. The complete adaptive network was **not functionally verified**.
