# Member 4 integration add-on — 19 October 2026

This is the new entry point. The older local `cnpro-member4` project is preserved.
Integration code lives under `monitoring_integration/` in `cnpro-member4-integrated`.
Publication updates root README navigation and adds ignore rules; it does not
rewrite any Member 1, 2 or 3 implementation.

## What changed since the original Member 4 version

The requested repository's `main` branch still contains only its initial README.
The new inputs actually live on `member-2` and `member3`; the published older
Member 4 version lives on `Member-4-updated`. `sources.json` pins all three commits.
Required source dependencies are materialized under `upstream/member2` and
`upstream/member3` by `prepare_upstream.py` from those exact Git commits.
Member 2's project is nested inside its `cnpro/` directory. No upstream file has
been patched or merged into the older configuration paths.

Generated `upstream/` copies are deliberately not committed: they already exist
on the teammate branches, and Member 3's original code contains a hard-coded lab
password. This avoids duplicating that credential in the Member 4 commit. The
setup script reads existing Git objects without fetching, checking out, merging,
changing branches or overwriting different files. Use a normal clone containing
the teammate histories; a GitHub ZIP/source archive alone lacks the required Git
objects. If those objects are missing, fetch the member-2 and member3 histories
and rerun setup. Do not manually edit generated copies; preserve original branch
ownership and configure credentials locally before any future real SSH use.

The add-on now:

- Resolves the six original scenarios against real ACL rules and actual engine
  state/event/recovery contracts, including **QUARANTINE** (the implemented name).
- Audits first-match ACL decisions, captures matching rule/line and identifies
  documentation conflicts without altering Member 2's policy.
- Imports and exercises Member 3's real PolicyEngine, StateManager,
  ThresholdTracker and RecoveryHandler with isolated per-trial persistence/logs.
  Switch output is explicitly recorded by a non-network stub; no SSH is sent.
- Supplies bounded real-lab HTTP traffic generation with explicit local source
  binding and an allowlist of actual project destinations. It cannot operate a
  Packet Tracer PC from the laptop.
- Adds stricter evidence/chronology/source validation before using the unchanged
  Member 4 CSV/JSON/summary/chart analyzer.
- Keeps software timings, configuration predictions and actual network
  measurements separate. No blocked placeholder is relabeled as a successful trial.

## Run the completed software workflow

PowerShell, from the new project root:

```powershell
Set-Location -LiteralPath 'C:\Users\samya\Desktop\CN proj\cnpro-member4-integrated'
python -B monitoring_integration/prepare_upstream.py
python -B monitoring_integration/run.py test
python -B monitoring_integration/run.py audit
python -B monitoring_integration/run.py replay --trials 3
```

Python 3.14.6 is available and was used. These commands need only the standard
library and the supplied files. `-B` avoids rewriting inherited bytecode caches.
The original engine optionally imports Paramiko but the recorder mode does not
use it. Paramiko is not installed here; actual SSH would require Member 3's
`upstream/member3/requirements.txt` and a matching reachable lab. The add-on never
starts Member 3's `simulate_event.py`, which would write state beside its source
and attempt real SSH. Existing source snapshots remain read-only by convention.

Each invocation prints a new `monitoring_integration/results/<kind>-<UTC>-<id>/`
directory. No older result is overwritten. The test command reports its suites
in `test_summary.json` and full output in `tests.txt`; it exits 1 on any failing
suite. Member 3's tests leave isolated synthetic fixtures in that run's `temp/`;
these are unit-test evidence, not measured network datasets.

Audit outputs: `environment.json`, `acl_checks.json`, `resolved_scenarios.json`,
`network_readiness.json`, `audit_report.md`. The audit checks the **new** Member 2
configuration, not the stale core export at the base project root. Its ACL parser
supports only syntax present in these inputs; unsupported rule forms fail instead
of silently receiving a predicted decision. It is not a switch/network emulator.
Declared capability state describes this inspected version and must be reassessed
if source branches or the runtime are changed.

Replay outputs: `engine_results.csv`, `engine_results.json`, `engine_summary.json`,
`engine_api_runtime.svg`, `replay_report.md` and per-trial state/event JSON,
`trace.json`, `engine.log`. Nine plans × three trials produce 63 real engine API
calls. The graph uses actual local API execution durations (monotonic clock),
including JSON persistence and logging overhead, summarized as means of per-trial
means. It measures neither packet detection nor effective switch response. State
and expected-state assertions can pass even when the recorder intentionally fails;
that failure case is successful only when the engine flags enforcement_failed.
The software dataset is deliberately rejected by the network importer.

## Actual policy and engine contracts

| Scenario/condition | Verified source behavior / expected network behavior |
|---|---|
| PC-RES1 → 192.168.50.10 HTTP/80 | Member 2 ACL permits; use as unaffected legitimate control |
| PC-STU2 → 192.168.50.12 HTTP/80 | Denied in normal VLAN10 already; this cannot prove a new adaptive restriction |
| PC-STU2 → research HTTP/80 | Permitted VLAN10, denied VLAN60/70; useful flow to demonstrate an effective change |
| PC-STU2 → remediation HTTP/80/DNS | Permitted VLAN10/60 as defined by ACL, denied VLAN70 |
| Recovery demonstration | Remediation HTTP while restricted, then restored internet HTTP after home VLAN/lease restoration |
| `auth_failure` | 3 events in 300 s → RESTRICTED |
| `cross_vlan_attempt` | 2 events in 600 s → RESTRICTED |
| `port_scan` / `spoofing` | 1 scan → RESTRICTED; 1 spoofing event → QUARANTINE |
| `policy_violation` | Does not restrict NORMAL by itself; while RESTRICTED, a recognized violation can escalate to QUARANTINE |
| Automatic recovery | 1800 s restricted hold or 7200 s quarantine hold, plus quiet history or remediated flag; actual code still requires hold after remediated |
| `manual_clear` | Immediate admin recovery API; must verify real home VLAN and permitted service separately |
| Enforcement failure | Engine still updates requested state/current_vlan and flags enforcement_failed; these stored values do not establish an applied switch VLAN |

No packet capture, ACL-log reader or automatic detector is supplied by Member 3.
Mapping a witnessed prohibited cross-VLAN attempt into `handle_event(...,
"cross_vlan_attempt")` is currently an explicit test injection. Do not claim HTTP
drops automatically trigger the engine. A production detector/Packet Tracer control
bridge remains a team integration dependency, not silently added here.

Two configuration/documentation conflicts are reproducibly reported:

1. **S12:** student-to-admin ICMP echo is permitted by the earlier broad ICMP
   rule before the later inter-VLAN deny. The verification document says DENY/PASS.
2. **Admin internet matrix:** "All Internet Ports" is broader than the ACL.
   For example TCP/25 to INTERNET-SRV is denied while the matrix says permit.

Other review points: the VLAN50 ACL's final `permit ip` is broader than its
response-only description. POLICY-HOST and switch management addresses share
VLAN40, so direct same-VLAN packets normally bypass routed core SVI filtering.
These findings are handed back as review items; no security rule was changed.

Member 3's prose also differs from its code and Member 2's ACL: its design note
describes a 60-second auth window (code: 300 seconds), and some tables allow
remediation in QUARANTINE (Member 2 VLAN70 ACL denies it). This add-on uses the
actual Python constants and actual Member 2 rules, records the discrepancy and
does not reconcile it by changing either member's files. Ask the team to confirm
which prose should be corrected before the final demonstration.

## Real traffic collection: only on a matching project test host

This environment has no .pkt file, no confirmed real/emulated lab runtime and no
locally assigned PC-RES1 lab address. Current traffic execution stops at source
binding (saved WinError 10049), before HTTP is sent. Do not configure your laptop's
global networking to force the test to run.

If the actual environment is **Packet Tracer**, open Member 1's topology, apply
Member 2's security configuration there and use the named PC's Desktop browser
or command prompt. Use Simulation mode for ARP/ICMP/TCP/HTTP/DHCP event/PDU
evidence. The original `monitoring/README.md` describes those actions. Wireshark
on Windows cannot capture simulated Packet Tracer packets. No .pkt export/control
API is assumed by this add-on.

If a **matching physical/emulated lab** becomes available, run the following
from its actual test host. Replace the source IP with its observed DHCP lease
and the configuration placeholder with a saved actual active CORE-SW export;
neither placeholder is evidence of a running configuration:

```powershell
python -B monitoring_integration/run.py collect-http --project-only --scenario authorized --source-ip 192.168.30.100 --vlan 30 --configuration static --configuration-snapshot ACTUAL_CORE_CONFIG.txt --count 5 --interval 1 --timeout 2 --trial 1
```

Allowed scenarios/source identities are authorized (PC-RES1), protected_access,
affected_research, remediation, recovery (PC-STU2) and admin_health_control
(PC-ADM1). PC-RES1 must use VLAN30; admin control VLAN40; STU2 home/restricted/
quarantine VLAN10/60/70. A source-IP/subnet check plus actual socket bind prevents
silent fallback to an unrelated laptop adapter. The operator must still confirm
the physical host identity and dedicated lab. Destination comes from the built-in
project target map; requests use HTTP GET `/` TCP/80 only. No DNS or redirects to
external services occur. `--project-only` is required operator confirmation.

Count is 1–100; interval .2–60 s after each response, timeout .1–10 s. Every
request uses a fresh TCP connection, reads at most 4096 response body bytes and
records status/error/duration. HTTP 2xx is counted as request success. These are
application request durations, not ICMP RTTs, and not a throughput test. A timeout
or HTTP failure alone cannot establish ACL denial. The saved configuration is
archived as provenance; its actual application must be verified in the lab.
This collector generates traffic and observations, but does not inject policy
events, move switchports, start capture or cause automatic DHCP renewal.

Successful collection saves `evidence/observations.json`, `requests.json` and
`active-config.txt` inside a new http run. Startup/collection failures are saved
in `preflight_or_collection_error.json`, CLI exits 1, and no completed observation
is asserted. Review any partial files rather than treating them as results.

For packet capture on a real **project-only** mirror interface, reuse unchanged
`monitoring/capture.py` with matching scenario/configuration and bounded duration,
as described in its README. tshark/driver/interface access is still required and
unavailable here. Review metadata and both return codes; existing script status
limitations are documented in the original walkthrough. Never use captured wire
byte counts as delivered application throughput without appropriate receiver data.

## Import genuine observations

The field reference is `observation_fields.json`; it is a schema guide, not an
example measurement. Create an array of real observations in the trial evidence
folder, or use a successful HTTP collector output. Then:

```powershell
python -B monitoring_integration/run.py import-network --input PATH_TO_REAL_OBSERVATIONS.json
```

That placeholder must be replaced with a real saved file. No network observations
exist in this delivery, so no successful network-import result is claimed. Import
uses the unchanged original analyzer after stronger validation. Output goes to a
new unique directory under `monitoring_integration/network_results/`, including
input/evidence copies, SHA256 manifest, CSV/JSON, statistical summaries, report,
conditional SVG comparisons and validation.txt.

Required metadata includes clock/evidence domain, actual source device/IP/VLAN,
destination/service, configuration/trial, expected ACL outcome and observations.
Both `configuration_snapshot` and `probe_evidence` must name existing archived
files. Detection timing requires original engine evidence; effective denial also
requires enforcement, healthy control and denial evidence. Restoration requires
enforcement/restoration evidence. All timing endpoints must be in the trial and
share a common declared clock domain. For Packet Tracer, consistently map the
simulation clock to a declared fixed epoch, label it simulated and retain the raw
simulation times. Never combine wall-clock engine timestamps with uncorrelated
simulation timestamps. The validator does not prove evidence truth or causality.

Metric definitions remain the original Member 4 definitions: condition→detection,
detection→first attributable denial, recovery condition→restored service (ms);
successful ICMP RTT samples; loss=(sent-received)/sent; receiver bytes×8/duration
for Mbps; authorized-request success and explicit transition-window disruption.
Missing values stay null/blank. Use rtt_ms=[] or omit it; null is not accepted for
that list. `<1 ms` is censored, not zero. Failed trials stay in raw results and
are excluded from summary means. Properly executed probes with no replies can
still be a measured 100%-loss trial, with no numeric RTT. Distinguish expected
offender denial from collateral disruption of unrelated legitimate users.

For a fair final comparison, use the same actual network/ACLs/service health,
workloads/cadence/capture points and at least three trials each with engine
disabled (static) and enabled (adaptive), resetting offender state/leases/counters.
Do not use the original open-routing architecture baseline as the secure static
comparator. Verify protected denials from the offender alongside successful
authorized health probes, then verify restored permissions after recovery.

## Files to hand over / remaining inputs

Hand over the new `monitoring_integration/` source/docs/schema and useful saved
audit/replay/test evidence locally. Version control excludes generated runs,
captures, caches and `upstream/` copies. Runtime imports require the unchanged root
`monitoring/evaluate.py` and the prepared `upstream/member3/policy_engine/`; keep those paths.
Do not substitute the test temp files or command-recorder traces for network data.

- Member 1: still supply `CN_Baseline_v1.pkt` (or the actual equivalent runtime),
  supported version, active device/lease mapping, service-health evidence and
  supported observation/control access.
- Member 2: review the two reproducible documentation/configuration mismatches;
  confirm expected outcomes, applied ACLs and a healthy admin-server control.
- Member 3: confirm detector-to-event source and runtime-to-switch bridge; review
  generic violation behavior, remediation hold and independent verification of
  commands. Provide actual timestamped logs from the integrated environment.

See `COMPLETION_REPORT.md` for executed tests, exact evidence paths and status.
No commit/push/upload is performed by these tools.
