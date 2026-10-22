# University Research Network — Handover and Technical Walkthrough

> Historical technical walkthrough of the 18 October version. For the refreshed
> local code and 20 October branch inspection, use
> [the current integration guide](monitoring_integration/README.md) and
> [current status](monitoring_integration/COMPLETION_REPORT.md). Functionality,
> source pins and pending items below are a dated record, not the latest status.

**Course:** BACSE203 P Computer Networks Lab  
**Project:** University Research Network with Adaptive Access Control and Dynamic Segmentation  
**Local folder:** `C:\Users\samya\Desktop\CN proj\cnpro-member4`  
**Inspection date:** 18 October 2026, Asia/Calcutta  
**Scope:** Repository inspection and explanation only. This task creates this document; it does not add features, alter existing project files, start traffic, or publish anything.

## Table of contents

1. [Original repository and provenance](#1-original-repository-and-provenance)
2. [Your responsibilities as Member 4](#2-your-responsibilities-as-member-4)
3. [Complete file audit](#3-complete-file-audit)
4. [Scripts, schemas and execution workflows](#4-scripts-schemas-and-execution-workflows)
5. [What the tests actually establish](#5-what-the-tests-actually-establish)
6. [Missing components and integration contracts](#6-missing-components-and-integration-contracts)
7. [Complete architecture and experiment sequence](#7-complete-architecture-and-experiment-sequence)
8. [Exact handover checklist](#8-exact-handover-checklist)
9. [Practical demonstration](#9-practical-demonstration)
10. [Maintenance notes and next actions](#10-maintenance-notes-and-next-actions)

**Read this first:** The current folder contains a network configuration package and working offline evaluation software. It does not contain a complete runnable adaptive network. The eight passing tests exercise software with synthetic fixtures. The saved results contain **18 blocked readiness entries**, not 18 traffic trials. No actual network measurement or full adaptive-network verification is available.

## 1. Original repository and provenance

### 1.1 Evidence used

The current local branch is `member1-network-architecture`; HEAD is `e866597362d03cb4eda2e2dbb80a7c7f759cdb6f`. Its Git tree contains **19 original files**. Git history records author **Pavan Adarsh** for their additions. This establishes the repository's recorded authorship, not independent proof of who physically typed each line. The local reflog contains the clone at this HEAD and no subsequent local commit.

The current tracked-file difference is only `README.md`: two navigation links were added for Member 4. `REPORT_MEMBER4.md` and `monitoring/` are untracked local additions. Their origin is supported by this conversation's earlier file-creation operations and their current contents; they have no committed Git authorship. This walkthrough is a new local document. No remote fetch was needed for this audit, so these statements describe the local checkout, not every branch or the current remote repository.

Available execution history shows a successful clone after an initial DNS failure, creation of the Member 4 files, an initial six-test run with two temporary-directory permission errors, a corrected six-test run, and a final eight-test run. The retained `monitoring/test-results.txt` records eight tests passing in 0.290 seconds. `monitoring/capture-preflight.txt` records that tshark was unavailable. The historical command returned exit code 2 for that preflight failure.

No tests were rerun during this documentation task: the saved transcript and actual test assertions were inspected instead. This avoids changing caches or generating new output folders. No claim here turns a historical software pass into a fresh network test.

### 1.2 Original intent and current implementation

The intended network separates students, faculty, researchers, administration and servers into VLANs. A VLAN is a separate Layer-2 broadcast domain. Access switches connect endpoints; trunks carry several VLANs between switches. CORE-SW routes between VLANs using Switch Virtual Interfaces (SVIs). DHCP supplies client addresses. EDGE-R translates internal addresses using PAT so many internal clients can share its outside address.

The proposed extension is a deterministic policy engine. It would detect defined violations, change a device's state, move its access port into a restricted or quarantine VLAN, and restore it after recovery. The original branch supplies the network design, Cisco configuration text, manual move commands and handoff requirements. It supplies no engine implementation and no security ACL policy.

| Original component | Present implementation in files | What is not established |
|---|---|---|
| VLANs and switching | VLAN definitions, port assignments, 802.1Q trunks, PortFast and shutdown unused ports | Applied/running status on a currently available network |
| Layer-3 routing | Seven CORE-SW SVIs, `ip routing`, core default route and edge return route | Current interface/link health or live reachability |
| DHCP | Six pools for VLANs 10/20/30/40/60/70; .1–.99 excluded | Current leases, renew timing or successful client readdressing |
| Management | Switch management addresses, local-login/SSH settings; phase snippets generate RSA keys | Real credentials, key existence or successful present-day SSH |
| Simulated internet | EDGE-R inside/outside NAT and address plan for INTERNET-SRV | Actual DNS/web server configuration in a usable topology |
| Server services | HTTP/HTTPS/FTP/DNS activation instructions and static addresses | Running server objects; no saved .pkt is present |
| Security ACLs | Requirements only; EDGE-R ACL 1 classifies NAT traffic | An implemented allow/deny access matrix or SVI filtering |
| Dynamic segmentation | CLI examples for VLAN reassignment and restoration | Event detection, thresholds, state machine, automation or recovery engine |
| Verification | T1–T15 procedure matrix and Member 1 report with PASS claims | Independent raw proof in this checkout; screenshots/topology are missing |

**Conclusion:** This is a useful partial setup package, not a self-contained runnable network. Configuration text is implementation material, but possession of text does not demonstrate that a network is operating.

### 1.3 Original file tree

```text
cnpro-member4/                  # original tracked tree at HEAD
├── README.md
├── REPORT_MEMBER1.md
├── configs/
│   ├── CORE-SW_phase2.cfg
│   ├── ACCESS-SW-A_phase3.cfg
│   ├── ACCESS-SW-B_phase3.cfg
│   ├── CORE-SW_phase4.cfg
│   ├── ACCESS-SW-A_phase5.cfg
│   ├── ACCESS-SW-B_phase5.cfg
│   └── EDGE-R_phase6.cfg
├── docs/
│   ├── 01_physical_topology.md
│   ├── 07_end_devices_configuration.md
│   └── 08_verification_matrix.md
├── handoff/
│   ├── MEMBER2_HANDOFF.md
│   ├── MEMBER3_HANDOFF.md
│   └── MEMBER4_HANDOFF.md
└── running-configs/
    ├── ACCESS-SW-A_running_config.txt
    ├── ACCESS-SW-B_running_config.txt
    ├── CORE-SW_running_config.txt
    └── EDGE-R_running_config.txt
```

There were no Python scripts, automated tests, capture files, result datasets, executable launch scripts, container definitions or simulator topology files in this tracked tree. The diagram is text in `REPORT_MEMBER1.md`; the cabling specification is Markdown. `CN_Baseline_v1.pkt` and the screenshots named in the report are references to absent artifacts.

### 1.4 Network addresses and physical placement

| VLAN | Role | Subnet | Gateway | Address allocation |
|---|---|---|---|---|
| 10 | Students | 192.168.10.0/24 | 192.168.10.1 | DHCP .100–.254 |
| 20 | Faculty | 192.168.20.0/24 | 192.168.20.1 | DHCP .100–.254 |
| 30 | Research | 192.168.30.0/24 | 192.168.30.1 | DHCP .100–.254 |
| 40 | Administration/management | 192.168.40.0/24 | 192.168.40.1 | DHCP .100–.254; static management below .100 |
| 50 | Servers | 192.168.50.0/24 | 192.168.50.1 | Static; no DHCP pool |
| 60 | Restricted | 192.168.60.0/24 | 192.168.60.1 | DHCP .100–.254; security policy pending |
| 70 | Quarantine | 192.168.70.0/24 | 192.168.70.1 | DHCP .100–.254; security policy pending |
| 999 | Blackhole/native | No IP subnet | None | Unused ports shut down; trunk native VLAN |

CORE-SW Gi0/1 connects to ACCESS-SW-A Gi0/1. CORE-SW Gi0/2 connects to ACCESS-SW-B Gi0/1. Both trunks allow VLANs 10,20,30,40,50,60,70 and use native VLAN 999 as written. CORE-SW Fa0/24 is a routed link at 10.0.0.1/30 to EDGE-R Gi0/0 at 10.0.0.2/30. EDGE-R Gi0/1 is 203.0.113.1/30, facing INTERNET-SRV at 203.0.113.2/30. That server is simulated internet, not an external attack target.

| Endpoint | Switch/port | Normal VLAN/address | Service or purpose |
|---|---|---|---|
| PC-STU1 / PC-STU2 | ACCESS-SW-A Fa0/1 / Fa0/2 | 10, DHCP | Student test clients; STU2 is designated offender |
| PC-FAC1 / PC-FAC2 | ACCESS-SW-A Fa0/3 / Fa0/4 | 20, DHCP | Faculty clients |
| PC-ADM1 / PC-ADM2 | ACCESS-SW-A Fa0/5 / Fa0/6 | 40, DHCP | Administration clients |
| POLICY-HOST | ACCESS-SW-A Fa0/7 | 192.168.40.50 | Intended policy management host; actual runtime missing |
| PC-RES1 / PC-RES2 | ACCESS-SW-B Fa0/1 / Fa0/2 | 30, DHCP | Research clients |
| SRV-RESEARCH | ACCESS-SW-B Fa0/3 | 192.168.50.10 | HTTP/HTTPS, TCP 80/443 |
| SRV-DB | ACCESS-SW-B Fa0/4 | 192.168.50.11 | FTP stand-in, TCP 21 control; data policy needs confirmation |
| SRV-ADMIN | ACCESS-SW-B Fa0/5 | 192.168.50.12 | HTTP/HTTPS, TCP 80/443 |
| SRV-REMEDIATE | ACCESS-SW-B Fa0/6 | 192.168.50.13 | HTTP and DNS |

Switch management: CORE-SW 192.168.40.1, ACCESS-SW-A 192.168.40.21, ACCESS-SW-B 192.168.40.22. POLICY-HOST must retain SSH TCP/22 access. DHCP UDP/67–68 must work after VLAN moves. Do not assume exact client leases from the host number: verify with `ipconfig` and `show ip dhcp binding`.

The design routes traffic between VLANs 60/70 and the rest of the network. Those VLAN names do not themselves enforce routed denial. Security requires Member 2's applicable filtering. A successful gateway ping after a VLAN move demonstrates local reachability, not effective quarantine.

## 2. Your responsibilities as Member 4

You turn the team's claims into reproducible evidence. Members 1–3 create paths, rules and decisions; you measure what those paths and decisions actually do to requests. You are not responsible for inventing missing access rules or substituting a mock state machine.

| Responsibility / objective | Inputs required | Existing approach | Expected output/evidence | Acceptance test | Dependency |
|---|---|---|---|---|---|
| Controlled traffic: exercise authorized and protected paths consistently | Usable topology, real leases, access matrix, engine triggers | Six scenario procedures in `monitoring/scenarios.json`; manually operate simulated PCs | Per-request expected/observed outcomes, transcripts and PDU events | Repeat the same source, destination, protocol, count and cadence across configurations | Member 1 environment; Member 2 expectations; Member 3 triggers |
| Capture: observe where traffic travels or stops | Simulation events, or dedicated real mirror interface and capture tools | Packet Tracer Simulation instructions; optional `capture.py` for tshark | Simulation screenshots/PDU details OR genuine pcapng plus metadata, not interchangeable | Correlate packets/events with a known trial and probe; inspect request/reply and denial evidence | Member 1 capture access; Member 2 ACL placement |
| Collect metrics: quantify response and performance | Matched timestamps, probe counters, RTT samples, request outcomes, transfer bytes if supported | Manually normalize observations into JSON; `evaluate.py` validates/calculates | Per-trial CSV/JSON with units, sample counts, nulls and notes | Independently recompute a trial from raw evidence; passing arithmetic tests support the implementation | All three members; especially timestamped Member 3 logs |
| Compare static/adaptive: assess security and legitimate-service cost | Same network/ACLs, engine disabled/enabled, repeated comparable trials | Group by scenario/configuration; unweighted trial summaries and conditional SVG bars | Mean/median/min/max/n plus rate comparisons and explanation | Equal workload, reset conditions, honest unavailable metrics; compare effective access as well as logs | Member 2 static baseline and Member 3 adaptive configuration |
| Evidence/provenance: make findings traceable | Original logs, configs, observations, screenshots/captures | Input snapshot, copied evidence files, SHA256 manifest, unique run folders | Each number linked to a real trial and its sources | Reopen archived evidence and regenerate outputs without confusing runs | Team-provided raw artifacts and clock information |
| Report/handover: enable maintenance and examination | Verified implementation and actual results | `REPORT_MEMBER4.md`, monitoring README, this walkthrough | Reproduction steps, honest status and known limitations | Teammate can run software and identify exactly which network checks remain blocked | Team agrees on completed integration evidence |

Why these matter: a state log can say QUARANTINED while routing still permits a protected web request. A denied request can also result from an offline server. You must show both the intended configuration/state change and the request outcomes, with a healthy authorized control client. Performance evidence must distinguish lost probes, successful RTT samples and affected legitimate requests.

## 3. Complete file audit

### 3.1 Complete Member 4 file tree

The following are the Member 4 additions or modifications observed locally, plus this newly created document. `.git/` contains inherited Git metadata rather than project deliverables and is excluded from the artifact tree. Both Python cache files are included so that the inventory does not silently omit generated files.

```text
cnpro-member4/
├── README.md                                  # inherited, modified navigation
├── REPORT_MEMBER4.md                          # added status report
├── HANDOVER_AND_TECHNICAL_WALKTHROUGH.md        # this document
└── monitoring/
    ├── README.md
    ├── requirements.txt
    ├── scenarios.json
    ├── evaluate.py
    ├── capture.py
    ├── test-results.txt
    ├── capture-preflight.txt
    ├── __pycache__/
    │   └── evaluate.cpython-314.pyc
    ├── tests/
    │   ├── test_evaluate.py
    │   └── __pycache__/
    │       └── test_evaluate.cpython-314.pyc
    └── results/
        ├── 20261018T102624Z-26207990/
        │   └── audit.json
        └── 20261018T102624Z-46c9c62f/
            ├── availability.json
            └── 20261018T102625Z-e561ed3d/
                ├── evidence_manifest.json
                ├── input.json
                ├── report.md
                ├── results.csv
                ├── results.json
                └── summary.json
```

There is no `monitoring/observations.json`, no `monitoring/captures/` directory, no saved network graph, no saved synthetic sample dataset, no standalone traffic-generation script and no separate graph-generation script. Synthetic fixtures exist inside the tests and are removed with their temporary directories. Charts, when supported by data, are generated inside `evaluate.py`.

### 3.2 Original files: individual purposes and verification

All paths below are relative to the project root. For every original file, provenance is inherited from the HEAD tree and Git author is recorded as Pavan Adarsh. Configuration files were read and compared with the documented topology; none was applied to a running network during Member 4's work. Markdown files were inspected, not executed. All 19 should be retained as the shared architecture package, with the README navigation update included.

| Exact path / file type | Contents, internal operation and inputs → outputs | Dependencies, verification and handover |
|---|---|---|
| `README.md` — Markdown | Originally one project-title line; current copy links to monitoring instructions and Member 4 report. Reader navigation only, no algorithm or runtime I/O. | HEAD provenance for title; conversation-supported Member 4 addition for links. Links point to existing files. Hand over modified version. |
| `REPORT_MEMBER1.md` — Markdown | Topology ASCII diagram, device roles, VLAN/address/port tables, configuration excerpts, T1–T15 PASS claims, screenshot catalog and ARP/VLAN discussion. Inputs: author's design/claimed tests; output: human report. | Latest change at e866597, added in aad0c26. Screenshot catalog and .pkt are absent. Claims not independently reverified. Hand over with this limitation. |
| `configs/CORE-SW_phase2.cfg` — Cisco CLI text | Enters enable/configuration mode, names core, disables DNS lookup, sets transparent VTP, creates VLANs 10–70/999, trunks Gi0/1–2, native 999 and allowed list; shuts Fa0/1–23 in 999; saves config. Input: core CLI in intended model; output: L2 configuration/NVRAM if applied successfully. | Added in 12f3e11. Requires cabling/models and console privileges. Static inspection only. Required handover. |
| `configs/ACCESS-SW-A_phase3.cfg` — Cisco CLI text | Builds VLANs/trunk Gi0/1, assigns Fa0/1–2 students, 3–4 faculty, 5–7 admin, enables PortFast, shuts unused Fa0/8–24/Gi0/2 and saves. | Added in ddb9014; depends on phase 2 and physical port plan. Text inspected, no live L2 test. Required. |
| `configs/ACCESS-SW-B_phase3.cfg` — Cisco CLI text | Builds VLANs/trunk Gi0/1; Fa0/1–2 research, Fa0/3–6 servers; PortFast; shuts unused Fa0/7–24/Gi0/2; saves. | Added in ddb9014. Depends on exact research/server cabling. Inspection only. Required. |
| `configs/CORE-SW_phase4.cfg` — Cisco CLI text | Enables routing, creates seven .1 SVIs, configures Fa0/24 at 10.0.0.1/30/default route via .2; DHCP exclusions/pools; local account/domain/RSA key generation/SSH VTY; saves. | Added in 7143d52. Requires phase 2, real local secrets and supported IOS commands. `<LAB_PASSWORD>` is placeholder, not usable proof of authentication. No live DHCP/routing/SSH execution. Required. |
| `configs/ACCESS-SW-A_phase5.cfg` — Cisco CLI text | Management Vlan40 .21/24 and gateway .1; domain, local admin/enable secrets, RSA/SSH setup and save. | Added in c975627. Requires phase 3, VLAN40 path and real credentials. Text inspection only. Required. |
| `configs/ACCESS-SW-B_phase5.cfg` — Cisco CLI text | Same management setup for .22/24, gateway .1. | Added in c975627. Requires B phase 3 and credentials. Inspection only. Required. |
| `configs/EDGE-R_phase6.cfg` — Cisco CLI text | Configures Gi0/0 .2/30 NAT inside, Gi0/1 203.0.113.1/30 NAT outside; return route for 192.168.0.0/16 via core; ACL 1 plus PAT overload; saves. | Added in a740595. Requires transit/core and external server configuration. ACL 1 is NAT selection, not an applied security filter. No live NAT test. Required. |
| `docs/01_physical_topology.md` — Markdown | Lists 18 devices and 17 cable connections with models, ports and cable types; human input for topology construction. | Added in 543f3c8. PC-ADM1 model cell says PC-ADM2, a documentation inconsistency requiring Member 1 confirmation. Does not instantiate a topology. Required. |
| `docs/07_end_devices_configuration.md` — Markdown | Static server/policy-host IPs, masks, gateways, DNS, services to enable and eight DHCP client placements. Input: operator; output: manual host setup when followed. | Added in 0aa0972. No actual server/service objects saved here. INTERNET-SRV details also appear in Member 1 report. Inspection only. Required. |
| `docs/08_verification_matrix.md` — Markdown | T1–T15 commands/actions and expectations; Pass/Fail cells are blank. No executable assertions. | Added in 3f9f911. Needs actual devices/topology to run. Distinguish this unfilled matrix from report PASS claims. Required. |
| `handoff/MEMBER2_HANDOFF.md` — Markdown | VLAN/server addresses, inbound CORE-SW SVI ACL placement, preservation of NAT/transit/DHCP and POLICY-HOST SSH. | Added in f00590f. Design contract only; does not supply actual ACLs or a full access matrix. Required for Members 2/4. |
| `handoff/MEMBER3_HANDOFF.md` — Markdown | Device/port/normal-VLAN map; configure-terminal/interface/access-VLAN commands for restriction/quarantine and return. | Added in f00590f. Depends on switch management and DHCP renewal. No engine source or state events. Required for Members 3/4. |
| `handoff/MEMBER4_HANDOFF.md` — Markdown | Names core Gi0/1, Gi0/2 and Fa0/24 observation points; states switching/routing/DHCP timing expectations. | Added in f00590f. No captured packets or supporting timing series supplied. Estimates are not Member 4 measurements. Required with caveat. |
| `running-configs/CORE-SW_running_config.txt` — IOS export text | Core VLANs, ports, SVIs, routing, DHCP, switch account/SSH/VTY settings; timestamps explicitly disabled. Used by `audit()` for substring checks. | Added in f00590f. Requires actual device to verify applied status. Secrets are redacted placeholders; RSA keys are not demonstrated by export text. No `ip access-group` present. Required reference. |
| `running-configs/ACCESS-SW-A_running_config.txt` — IOS export text | Full supplied A VLAN/port/management/SSH reference, including unused-port shutdown. | Added in f00590f. Static reference, not a console transcript proving operation. Required. |
| `running-configs/ACCESS-SW-B_running_config.txt` — IOS export text | Full supplied B VLAN/port/management/SSH reference. | Added in f00590f. Static reference, no live link or lease proof. Required. |
| `running-configs/EDGE-R_running_config.txt` — IOS export text | Router interface addressing, NAT directions, route, NAT ACL/PAT statement and basic console/VTY sections. | Added in f00590f. No active translations included. No policy engine management API. Required. |

The phase `.cfg` files are CLI sequences for the simulator/device, not PowerShell or Python programs. Phase 4/5 start with `configure terminal`, so the operator must already have privileged EXEC access. Apply phases in order only after confirming the exact target device. Running-config exports are references, not a guaranteed drop-in substitute for all initialization steps, especially keys and credentials.

### 3.3 Member 4 source and documentation: each file

**`monitoring/evaluate.py` — Python source, created for Member 4.** The main offline evaluation program. It imports only standard-library modules; `ROOT` locates the repository from the script path and `METRICS` names nine numeric outputs. Its public execution choices are `audit`, `blocked`, and `analyze`. Important functions: `stamp`, `delta`, `count`, `rate`, `calculate`, `audit`, `new_run`, `analyze`, and `main`. Inputs are documented config text, `scenarios.json` for readiness records, or an operator-created JSON array plus evidence files. Outputs are unique audit or analysis run folders. The exact flow and validation are in Part 4. Eight tests exercise selected helper/import/summary/chart paths; historical CLI runs exercised audit and blocked. No automatic engine-log parser, network probe runner, packet parser or live state checker exists here. Required handover.

**`monitoring/capture.py` — Python source, created for Member 4.** A command-line wrapper around an installed `tshark`. `main()` parses interface/configuration/scenario/duration and confirmation flags; constant `FILTER` scopes capture to documented address ranges. It imports `new_run` from the neighboring `evaluate.py`. It runs a bounded capture followed by offline `io,stat,1` statistics, saves metadata/logs and prints the output path. Input requires a verified project-only real interface; it cannot access Packet Tracer's internal simulation. Output files and failure branches are in Part 4. The missing-tool branch was actually executed and recorded. Real capture, filter behavior, statistics and timeout behavior were not functionally exercised; the eight tests do not cover this file. Required handover, labeled partially verified.

**`monitoring/scenarios.json` — JSON configuration/procedures, created for Member 4.** Six objects with `id`, `source`, `destination`, `service`, `action`, `expected`. It is a human traffic procedure catalog, not executable traffic generation. `blocked` reads only each `id` to create readiness rows; it does not execute `action` or assert `expected`. Test scenarios and their pending expectations are traced in Part 4. Historical blocked execution confirms the file can be loaded; no network scenario was run. Required handover.

**`monitoring/tests/test_evaluate.py` — Python unittest source, created for Member 4.** Adds the monitoring directory to `sys.path`, imports evaluation helpers, and defines `EvaluationTests` with eight `test_*` methods. Uses only the standard library, temporary fixture files and project-local `TemporaryDirectory` directories. It writes short synthetic JSON/text fixtures, analyzes them and deletes the temporary directories on exit. Assertions cover arithmetic, selected invalid inputs, evidence copying, duplicate keys, missing files, chart existence, failed exclusion and unique outputs. Part 5 details exact coverage. Historical final execution: eight passed. Required handover; synthetic fixture data must not be presented as network evidence.

**`monitoring/README.md` — Markdown guide, created for Member 4.** Contains tool prerequisites, CLI commands, inventory, team dependencies, Packet Tracer traffic and capture procedures, real-interface tshark workflow, schema and metric definitions. Input/output is human instruction; it depends on the scripts and missing team components. Read against code during this task. Some simplifications need the qualifications in Part 10: the audit is not an immutable original-tree audit; timestamp/RTT input has specific constraints; capture error handling is incomplete. Keep this existing file unchanged and hand it over together with this walkthrough.

**`monitoring/requirements.txt` — Comment-only dependency note, created for Member 4.** States Python >=3.10, standard library, optional Packet Tracer and optional Wireshark/tshark/driver. It contains no installable package specifications and cannot install the simulator or capture driver. The available interpreter is Python 3.14.6. No pip dependency installation was needed. Preserve and hand over; see Python ISO timestamp compatibility note in Part 10.

**`REPORT_MEMBER4.md` — Markdown report, created for Member 4.** Describes implementation status, source inspection, missing network components, exact historical result paths, eight passing software tests, preflight failure, metric definitions and reproduction. Human report, not a generated measured comparison. Its claims were checked against code, Git state and saved outputs; the main status claims are supported. Its file list omits the small preflight transcript/cache files, which this audit includes. Required handover.

**`README.md` — inherited Markdown with Member 4 modifications.** Only navigation was added. `git diff -- README.md` distinguishes those lines from the original title. No feature or architecture changes. Include in handover so teammates can find the tools.

**`HANDOVER_AND_TECHNICAL_WALKTHROUGH.md` — this new Markdown document.** Explains the actual local files and gaps from Parts 1–9 of the request. Inputs are the audited source, history and saved artifacts; output is this standalone handover. No runtime package dependency. Checked for referenced file coverage and preservation of existing files. Required handover.

### 3.4 Generated outputs: every existing artifact

These long paths are written in full to avoid confusing a readiness record with a traffic dataset. All were generated in the prior Member 4 work, as supported by execution history and their contents. They are not inherited Git files.

| Exact relative path / type | Contents and internal meaning | Input, regeneration, verification and handover |
|---|---|---|
| `monitoring/test-results.txt` — text | Final unittest stdout/stderr: eight named tests, 0.290 s, OK. | Earlier PowerShell pipeline captured unittest output. Inspected now, not rerun or overwritten. Retain as historical software evidence. Future durations need not match. |
| `monitoring/capture-preflight.txt` — text | argparse usage and `tshark unavailable; no capture performed`. | Earlier `capture.py` invocation with interface `unavailable`, static/performance, 1 second, output redirected to text. Inspected now. Retain to document the limitation; not packet evidence. |
| `monitoring/results/20261018T102624Z-26207990/audit.json` — JSON | checked_at, empty pkt_files, false core_security_acl_applied, true routing_enabled, tool paths/nulls, 19 SHA256 entries and limitation strings. | Generated by `evaluate.py audit` at 10:26:24 UTC (15:56:24 IST). Checks files/text, not a running network. New audit creates a new run and may include additional root docs. Preserve historical copy. |
| `monitoring/results/20261018T102624Z-46c9c62f/availability.json` — JSON | 18 objects = 6 scenario IDs × 3 configurations, trial=1, blocked, readiness timestamp and notes; no measured counters. | Created by `blocked` reading scenarios.json. All timestamps record availability check, not traffic start/end. Parsed and counted now. Required context for readiness outputs. |
| `monitoring/results/20261018T102624Z-46c9c62f/20261018T102625Z-e561ed3d/input.json` — JSON | Byte-for-byte snapshot of availability.json. | `analyze()` copies source bytes. Equality verified during this task. Retain for exact historic input; rerun analyze against it or availability.json for equivalent numerical content in a new folder. |
| `monitoring/results/20261018T102624Z-46c9c62f/20261018T102625Z-e561ed3d/evidence_manifest.json` — JSON | Empty object `{}`. No executed trials required or supplied evidence files. | Generated by analyze; normally maps source absolute paths to copied filenames and SHA256 hashes. Inspected empty, not missing. Retain; emptiness does not imply a successful network test. |
| `monitoring/results/20261018T102624Z-46c9c62f/20261018T102625Z-e561ed3d/results.json` — JSON | 18 readiness rows plus all nine metrics null and rtt_sample_count=0. | `calculate()` then `analyze()`; rows/blocked statuses verified. Required readiness dataset, explicitly not a network result set. |
| `monitoring/results/20261018T102624Z-46c9c62f/20261018T102625Z-e561ed3d/results.csv` — CSV | Same 18 rows; sorted union of keys supplies columns. None becomes blank; nested structures would be JSON strings. | DictWriter output from processed rows. Parsed as 18 rows now. Human/spreadsheet inspection format; retain with JSON so null meaning is clear. |
| `monitoring/results/20261018T102624Z-46c9c62f/20261018T102625Z-e561ed3d/summary.json` — JSON | 162 records = 6 scenarios × 3 configurations × 9 metrics. All n=0; all mean/median/minimum/maximum null. | Generated by grouping only measured rows with non-null values. Counts and n values verified. Retain; no aggregate network finding exists. |
| `monitoring/results/20261018T102624Z-46c9c62f/20261018T102625Z-e561ed3d/report.md` — generated Markdown | Summary table with unavailable values and trial status/notes. | Generated by analyze from the same rows, not an independent report or engine log. Read and cross-checked with dataset counts. Retain as the readable readiness report. |
| `monitoring/__pycache__/evaluate.cpython-314.pyc` — Python bytecode | Interpreter cache for evaluate imports; binary, not maintained source or evidence. | Automatically regenerated on normal import under CPython 3.14 unless disabled with -B; exact bytes can differ by environment. File presence inspected, not used as source provenance. Optional; omit from team submission. |
| `monitoring/tests/__pycache__/test_evaluate.cpython-314.pyc` — Python bytecode | Interpreter cache for the test module. | Same regeneration rule; no distinct functionality beyond test source. Presence inspected. Optional; omit from submission. |

Generated graphs would be `comparison-0.svg`, `comparison-1.svg`, etc., within an analysis run folder, and evidence copies would be `evidence/<index>-<original-filename>`. Neither exists in the saved readiness run. Do not list them as completed measurements. Useful future generated evidence should be retained with the producing input; caches and temporary test fixtures need not be handed over.

## 4. Scripts, schemas and execution workflows

### 4.1 Execution location and dependencies

Use PowerShell in this folder:

```powershell
Set-Location -LiteralPath 'C:\Users\samya\Desktop\CN proj\cnpro-member4'
python --version
```

Observed interpreter: Python 3.14.6. Evaluation/tests use only built-in modules. No server, network emulator, engine, browser or tshark is needed for offline calculations. For reproducibility, use this verified interpreter or a compatible Python version; Python 3.10's ISO parser does not accept every timestamp form that later versions do.

All following commands describe existing entry points, not newly implemented functionality. Commands that need unavailable components are marked conditional. Diagnostic placeholders must be replaced with verified local inputs, not typed as if those files/interfaces already existed.

### 4.2 `evaluate.py`: helpers and calculation flow

`main()` parses `command`, optional `--input` and `--output`. Default output base is the script-derived repository's `monitoring/results`. `new_run(base)` builds `UTC timestamp + '-' + first eight UUID hex characters`, e.g. `20261018T102624Z-26207990`, and uses `mkdir(..., exist_ok=False)` to avoid silent overwrite. Each invocation prints its resulting folder. A timestamp collision is highly unlikely with UUID suffixes; an actual collision raises rather than merging outputs.

| Function | Internal behavior | Key limitation |
|---|---|---|
| `stamp(value)` | `datetime.fromisoformat`, requires tzinfo | Does not synchronize clocks or certify timezone truth |
| `delta(row,start,end)` | Null if either endpoint absent/null; otherwise millisecond difference; rejects negative difference | Does not require the event to lie within trial start/end or check complete transition order |
| `count(row,key)` | Nonnegative integer or None; exact integer type rejects booleans | No plausibility check against the raw transcript |
| `rate(...)` | Requires counter pair together; successes cannot exceed attempts; zero attempts → None | An operator must define what a successful request means |
| `calculate(row)` | Computes nine metrics and validates samples/counter pairs; checks trial duration is not negative | No live probe, log parsing, event attribution or policy assertion |
| `audit()` | Reads core export; scans files outside .git and monitoring; records hashes/tool paths/text checks | Static snapshot with hard-coded limitation messages, not a runtime readiness engine |
| `analyze(source,base)` | Parses/validates input, collects evidence, saves outputs, summarizes and charts | Trusts supplied observations; cannot independently verify physical events |

`calculate()` outputs:

| Field | Formula / unit | Evidence needed |
|---|---|---|
| `detection_ms` | (detected_at − condition_at) × 1000 | Defined condition occurrence and actual monitor detection |
| `response_ms` | (effective_denial_at − detected_at) × 1000 | Service denial attributable to enforcement, after detection |
| `recovery_ms` | (restored_at − recovery_condition_at) × 1000 | Defined recovery condition and permitted service restored |
| `latency_ms` | Arithmetic mean of successful `rtt_ms` samples | Individual numeric RTTs; number reported as rtt_sample_count |
| `packet_loss_pct` | (probes_sent − probes_received) / probes_sent × 100 | Sent requests and matched replies |
| `throughput_mbps` | transferred_bytes × 8 / transfer_seconds / 1,000,000 | Delivered application bytes and positive transfer duration |
| `disruption_pct` | (transition_attempted − transition_succeeded) / transition_attempted × 100 | Legitimate request outcomes in the defined transition window |
| `success_pct` | legitimate_succeeded / legitimate_attempted × 100 | Verified authorized application responses |
| `unauthorized_success_pct` | unauthorized_succeeded / unauthorized_attempted × 100 | Matrix-denied attempts that actually succeeded |

The timestamp factor is milliseconds per second. The throughput formula represents application goodput if bytes are receiver-verified payload bytes. A packet capture's total wire bytes are not automatically that quantity. Detection is not defined for a static configuration with no monitor; leave it null, explaining why. Do not invent zero isolation delay for static ACLs.

If 4 probes are sent and none returns, loss is 100% and latency is null. If none is sent, loss is null. Numeric zero means a measured zero; null means unavailable/not applicable. `<1 ms` in Packet Tracer output is an upper bound, not zero: omit it from numeric RTT samples and document the censored count. If only larger RTT samples are averaged, disclose that the numeric mean excludes censored samples and may be biased.

### 4.3 Repository audit workflow

```powershell
python -B monitoring/evaluate.py audit
```

Prerequisites: Python and the existing core running-config file. Reads `running-configs/CORE-SW_running_config.txt`, recursively inspects non-monitoring/non-.git files and asks `shutil.which` about python/tshark/tcpdump/PacketTracer. Writes one `audit.json` inside a new unique run directory and prints that directory.

Success is file creation, not a working network. The historic audit reports no .pkt, no core `ip access-group`, routing enabled and missing capture tools on PATH. Missing core file raises `FileNotFoundError`; malformed/missing environment dependencies are not automatically repaired.

**Important scope:** `audit()` does not use Git to select original files. It includes current root documents such as Member 4 reports if they exist at run time; it excludes all files under monitoring. The saved old audit has 19 hash entries because those were present then. A fresh audit after this walkthrough will have a different inventory. Security/routing checks are string searches, not IOS parsers. Its three limitation strings are hard-coded and will remain until the software is deliberately updated; never use those strings alone to decide whether newly integrated components work.

### 4.4 Readiness / blocked workflow

```powershell
python -B monitoring/evaluate.py blocked
```

Prerequisite: existing `monitoring/scenarios.json`. Creates outer unique folder, loads each scenario ID, crosses six scenarios with three configuration labels, uses a single UTC readiness timestamp for start/end, writes `availability.json`, then calls `analyze()` with that outer folder as base. Analysis makes a second nested unique folder. Printed path points to the inner analysis folder.

Successful output is 18 blocked records, null metrics, n=0 summaries and a report saying unavailable. No traffic is sent and no actual prerequisite probe is performed by `blocked`: its status/notes are a deliberately recorded limitation, not an automated fresh diagnosis. Use it only when that limitation still applies. Bad JSON or missing scenarios fails normally with a Python exception. It never starts an engine.

### 4.5 Observation schema and validation

`analyze` expects a JSON **array** of row objects. This is an offline input contract, not Member 3's actual event format (none was supplied). Source/destination/protocol and expectations currently go in `notes` or optional extra fields; there are no required typed source-IP/service fields.

| Input field | Required/type and interpretation |
|---|---|
| `scenario` | Required; conventionally an ID from scenarios.json, but membership is not enforced |
| `configuration` | Required; exactly `architecture_baseline`, `static`, or `adaptive` |
| `trial` | Required positive integer; scenario/configuration/trial tuple must be unique within the import |
| `start_at`, `end_at` | Required timezone-aware ISO8601 timestamps; end cannot precede start |
| `status` | Required: measured, failed or blocked |
| `notes` | Required key; human explanation of conditions/outcome/uncertainty; no nonempty-string validation |
| `evidence` | Required nonempty iterable of file paths for measured/failed rows; documentation expects a list of paths within input folder |
| Timing endpoints | condition_at, detected_at, effective_denial_at, recovery_condition_at, restored_at; omit or use null when unavailable |
| Counter pairs | probes_sent/received; legitimate_attempted/succeeded; unauthorized_attempted/succeeded; transition_attempted/succeeded; both supplied or both absent/null |
| `rtt_ms` | Optional list of finite nonnegative numeric samples; **omit or use [] when unavailable, not null** |
| Transfer pair | transferred_bytes nonnegative integer and transfer_seconds positive finite number, together or both absent/null |

`analyze()` loads UTF-8 with optional BOM. It verifies required keys, enum values, positive integer trial, duplicates, timestamp awareness, counters, finite RTT values and transfer duration. RTT sample count cannot exceed a supplied reply count. A blocked row with any computed numeric metric is rejected. Executed rows must reference existing readable evidence. Resolved evidence must stay within the input folder, preventing `../` escape. The importer reads and later copies evidence bytes, mapping original absolute paths to archive locations and hashes.

It does **not** require a known scenario ID, enforce notes content, robustly type-check every object/path list, confirm that any paired timestamp lies inside the trial, require engine evidence for a timing metric, inspect evidence meaning, or assert expected policy behavior. A status of measured is operator-supplied. An input file that is valid JSON can still be scientifically invalid. Unknown extra fields are preserved; non-serializable/nonfinite extra values can still fail output writing. Errors generally propagate as exceptions with a traceback; there is no recovery wizard.

The README's broad statement that optional fields may be null has an exception: `rtt_ms=null` fails the list check. The code is authoritative; leave that field out or use an empty list. These are documented limits, left unchanged in this task.

### 4.6 Analyze existing saved input today

```powershell
python -B monitoring/evaluate.py analyze --input 'monitoring/results/20261018T102624Z-46c9c62f/availability.json'
```

This supported command uses an actual present input file and needs no network. It creates a new analysis run with the same blocked/null numerical content. It does not overwrite the old run. It was not rerun during documentation; the saved input was inspected directly instead.

Once genuine observations exist, the existing documented command is:

```powershell
python -B monitoring/evaluate.py analyze --input monitoring/observations.json
```

**Conditional:** `monitoring/observations.json` does not exist now. Create it from genuine observations, not by copying synthetic unit-test numbers. Keep evidence files in its directory or subdirectories. Until then, this command will correctly fail with a missing-file error. `--output` can select another local base directory for either analysis or audit/readiness outputs.

Flow inside `analyze()`:

1. Load rows and validate/calculate every trial; read required evidence before creating the output directory.
2. Create a unique folder and copy input bytes to `input.json`.
3. Copy distinct evidence sources as `evidence/0-name`, `evidence/1-name`, etc.; save manifest hashes. A repeated reference to the same resolved file is copied once.
4. Save `results.json`: original row fields plus calculated metrics and RTT sample count. Existing supplied keys matching metric names are replaced by calculated values.
5. Build CSV fields as the sorted union of all processed keys. JSON null becomes a blank CSV cell. List/dict cells are JSON-encoded strings.
6. Group by scenario/configuration. For each of nine metrics, select non-null values only from measured rows. Report n, mean, median, minimum, maximum. Failed/blocked trials remain in results and status report but contribute no values to summaries.
7. Write `summary.json`; generate comparative SVGs if sufficient configuration means exist.
8. Write `report.md` with a summary table and notes for every trial, then return/print the directory.

The summary is an unweighted mean of trial-level percentages/means, not a pooled request-weighted success rate. If trial sample sizes differ, these differ mathematically; keep sample sizes equal or explain the difference. Standard deviations, confidence intervals and significance tests are not implemented. File generation is not transactional: a late disk/encoding/serialization error may leave partial output. Inspect all artifacts after an error rather than assuming a complete report.

### 4.7 Graph generation

There is no graph command separate from `analyze`. For each scenario/metric it selects configuration summaries with n>0. Fewer than two configurations → no graph. With two or three it emits an SVG bar chart, 850×200, white background, blue bars. Bar width is 450×configuration mean/max mean (with max replaced by 1 when all values are zero). Labels include configuration, mean and n. Metric name supplies units (ms, percent or Mbps). File sequence is `comparison-<index>.svg`; the index is assigned during iteration, not a stable metric ID.

These are simple static trial-mean comparisons without uncertainty bars. A graph is not automatically evidence of a fair comparison. The chart test asserts an SVG file exists, not visual correctness. No real result SVG exists now because every recorded readiness metric has n=0.

### 4.8 Traffic-generation procedures

No script sends project traffic. `scenarios.json` is used manually in the actual simulated hosts. The following commands/actions come from existing files; they are conditional on the usable topology and must not be run from the laptop as a substitute source.

| Scenario ID | Source → destination / service | Existing action and expected evidence | Missing prerequisite / caution |
|---|---|---|---|
| authorized | PC-RES1 → 192.168.50.10 HTTP/80 | Desktop Web Browser, enter `http://192.168.50.10`, five requests/trial; save responses/PDU details | Member 2 must confirm authorized expectation; all routed architecture-baseline pairs are intended reachable |
| protected_access | PC-STU2 → 192.168.50.12 HTTP/80 | Browser `http://192.168.50.12`, five requests at one-second intervals; record actual outcomes | Unauthorized designation pending real access matrix; architecture baseline should permit, not deny |
| violations | PC-STU2 on ACCESS-SW-A Fa0/2 → 192.168.50.12 HTTP/80 | After real threshold/cadence supplied, make threshold+1 attempts and retain engine events plus service probes | No defined threshold or log format currently exists; repeated blocked attempts alone are not an implemented trigger |
| legitimate_transition | PC-RES1 / PC-STU2 → .50.10 / .50.13 HTTP/80 | One request/s for 10 s before, throughout and 10 s after violation; separate per-flow counters | Affected remediation permissions require Member 2; use actual timing method and avoid treating page caching as new network requests |
| recovery | PC-STU2 → .50.13 remediation plus approved restored service | Apply actual recovery condition; `ipconfig /renew` after normal VLAN restoration; permitted probe once/s | Catalog names remediation .13 but says restored normal target must be matrix-approved; choose/record it after Member 2 confirms |
| performance | PC-RES1 → 192.168.50.10 ICMP | Desktop Command Prompt: `ping 192.168.50.10`; repeat until 20 probes/trial; keep full transcript | Do not assume a specific ping count flag; none is provided in procedures. Record censored RTTs honestly |

Run at least three comparable trials/configuration when practical. Browser actions are a test procedure, not a guarantee of exact scheduling or a fresh TCP connection every time. Save the actual request timeline and disable/control caching through an agreed repeatable procedure if it affects observations. No script currently enforces cadence or counts. Collect expected and observed outcome separately; JSON input has no built-in policy pass/fail evaluator.

### 4.9 Packet Tracer observation versus real packet capture

Packet Tracer's simulated packets are internal to that application. Capturing the laptop's Wi-Fi/Ethernet adapter will not turn them into real project packets. The existing supported procedure is: use Simulation mode, select ARP/ICMP/TCP/HTTP/DHCP event filters as applicable, clear previous events, run the selected scenario, inspect inbound/outbound PDU details and save screenshots plus the simulation clock and topology copy. Label these as simulated PDU evidence. No .pkt export script, simulation automation or PCAP export facility is implemented here.

For a **separate real/emulated project environment** with a dedicated interface, optional tshark automation is available. Prerequisites: installed tshark and capture driver/permissions, verified project-only interface, matching topology and a recorded observation point. `--project-only` is operator confirmation, not an automated isolation check. Address filtering alone cannot establish that a shared host interface belongs to this project.

```powershell
tshark -D
```

Conditional diagnostic: lists real capture interfaces when tshark exists. It will currently fail to resolve as a command if no tshark is installed/on PATH. It does not list Packet Tracer virtual devices.

After identifying a real interface, replace the placeholder below with its exact ID:

```powershell
python -B monitoring/capture.py --interface PROJECT_INTERFACE --project-only --configuration static --scenario performance --seconds 30 --tagged
```

This is a supported CLI form, not an executable demonstration against a presently available project interface. `--interface`, `--project-only`, `--configuration` and `--scenario` are required. Configuration choices are the same three analysis labels. `--seconds` defaults to 30 and accepts 1–300. `--output` defaults to `monitoring/captures`. `--tagged` is optional and should be omitted for untagged access/transit observations.

Capture flow:

1. Validate arguments/duration and resolve tshark with `shutil.which`. Missing tool triggers argparse error before any output directory is created.
2. Create `monitoring/captures/<configuration>/<unique-run>/`.
3. Build capture filter exactly as `(net 192.168.0.0/16 or net 10.0.0.0/30 or net 203.0.113.0/30)`. Tagged option adds `or (vlan and <same filter>)`, intended to cover one 802.1Q tag as well. This filter has not been validated on a live interface here.
4. Run tshark with interface/filter, duration stop, filesize:10240 stop, snap length 128 and pcapng output. A 128-byte snapshot can still include payload and limits later payload inspection. File cap is approximately 10 MB as interpreted by tshark's filesize setting.
5. Wait up to seconds+15. On normal process completion, save stdout+stderr to `capture.log` and returncode to metadata.
6. If capture returncode is zero, run tshark offline with `-q -z io,stat,1`, save `packet_statistics.txt`, record analysis_returncode. It has a separate 30-second timeout.
7. Always attempt to save `metadata.json` in the try/finally block, including command, start/end times, scenario/configuration, note and return/error fields. Print the path. Nonzero/missing capture returncode causes exit 1.

On a normally completed successful capture expect `traffic.pcapng`, `capture.log`, `packet_statistics.txt` and `metadata.json` with both return codes zero. Check them; the program does not validate meaningful packet contents. Wrong interface/permissions/filter usually produce tshark errors in the log. A timeout kills the created child via subprocess handling, not unrelated processes. It does not roll back any network configuration because it never creates one.

There are limitations: a timeout during the statistics stage uses the same generic capture-timeout message; a failed statistics return code can still leave overall CLI exit zero because final status checks only capture returncode. An unexpected launch/I/O error can propagate. Keyboard interruption handling is not comprehensive. Review metadata and logs before calling a capture successful. These paths have not been tested here and were not modified for this handover.

The historical preflight command was:

```powershell
python -B monitoring/capture.py --interface unavailable --project-only --configuration static --scenario performance --seconds 1
```

It recorded `tshark unavailable; no capture performed`, exit 2. The interface was never opened. Use the saved transcript to explain today's limitation; do not keep invoking it after tshark becomes available as though it were a valid capture.

### 4.10 Wireshark/tshark analysis and tcpdump status

For a **real saved capture**, open its pcapng in Wireshark and correlate the known endpoints and trial times. Existing suggested display filters are `icmp`, `dhcp`, `http`, `vlan.id == 60` and `ip.addr == 192.168.50.12`. Wireshark filter field names/version availability require confirmation in the installed tool; none was run here.

Existing optional commands (replace the placeholder with a real saved path):

```powershell
tshark -r PATH_TO_CAPTURE -q -z io,stat,1
tshark -r PATH_TO_CAPTURE -Y icmp -T fields -e frame.time_epoch -e ip.src -e ip.dst -e icmp.type -e icmp.seq
```

First command prints per-second capture statistics. Second prints selected ICMP packet fields, not ready-made RTT/loss metrics: matching requests/replies, direction, identifiers and duplicate handling still require analysis. `evaluate.py` does not ingest this output automatically. An observer may see duplicate traffic in a mirror; do not count it as additional requests.

`tcpdump` is only checked by `audit()` and mentioned as a possible external capture tool in the task context. There is **no tcpdump wrapper or tested tcpdump workflow** in this folder, and the historic audit found none on PATH. No tcpdump command is needed to reproduce the implemented tools. Wireshark is a GUI inspection tool; tshark is its CLI relative used by `capture.py`.

### 4.11 Workflow connections

```text
core export + filesystem ────────────────> evaluate.py audit ─> audit.json
scenarios.json ──────────────────────────> evaluate.py blocked
                                              └─> availability.json ─> analyze()

real topology + team policies/engine
   └─> manual scenario traffic + original evidence
          └─> operator-created observations JSON ─> evaluate.py analyze
                 ├─> input snapshot + copied evidence + hash manifest
                 ├─> trial CSV/JSON
                 ├─> summaries + Markdown report
                 └─> comparison SVGs, when measured data supports them

optional real interface ─> capture.py ─> pcapng/log/stats/metadata
                                      └─> human correlation/observations (no automatic importer)

tests/test_evaluate.py ─> synthetic temporary inputs ─> selected evaluation functions
```

Audit, blocked and tests are independent of a live network. Capture depends on real capture support but only imports the shared folder-naming helper. Analysis does not start capture, traffic or an engine. It accepts genuine evidence collected through either supported observation route after a human normalizes the input.

## 5. What the tests actually establish

### 5.1 Saved software execution record

Relevant file for every test: **`monitoring/tests/test_evaluate.py`**, class **`EvaluationTests`**. Historical execution is confirmed by the matching names in `monitoring/test-results.txt` and earlier execution history. Final recorded result is eight passed in 0.290 s. The documentation task inspected those files without overwriting the record.

| Test name | Actually executed / result | Exact assertion coverage | What it proves | What it does not prove |
|---|---|---|---|---|
| `test_metrics` | Yes, recorded ok | 4 sent/3 received →25% loss; RTT [1,2,3]→2 ms; 1,000,000 bytes/2 s→4 Mbps; detection 1000 ms; response 2000 ms; success 80%; disruption 50% | Arithmetic on these synthetic inputs | Real timestamps, delivered bytes, ACL behavior; unauthorized success is not asserted here |
| `test_missing_and_failed_probes` | Yes, recorded ok | Empty row yields all metric values None; 4/0 gives 100% loss and no latency; 0/0 loss is None | Missing-data and selected failed-probe handling | Real failed probe collection or distinguishing ACL denial from outage |
| `test_invalid` | Yes, recorded ok | Selected cases raise ValueError: successes>attempts, negative/incomplete counter input, NaN RTT, zero transfer duration, naive timestamps, reversed detection timing | Rejection of these invalid input cases | Every malformed schema/type, all ordering/clock errors or scientific validity |
| `test_import_and_evidence` | Yes, recorded ok | Synthetic input analyzed twice to different folders; loss mean=100; evidence copy exists; duplicates rejected; absent evidence raises FileNotFoundError; malformed JSON raises ValueError | Selected import/copy/summary/error paths and unique runs | Copied file hash correctness is not explicitly asserted; CSV cells/report content are not fully asserted; evidence is not real traffic |
| `test_unique_output` | Yes, recorded ok | Two `new_run` calls produce different Paths | Run separation for two calls | High-concurrency/collision stress or protection against every external filesystem issue |
| `test_recovery` | Yes, recorded ok | Two-second synthetic recovery interval →2000 ms | Recovery subtraction/unit conversion | Real restored connectivity or recovery engine correctness |
| `test_chart_and_failed_exclusion` | Yes, recorded ok | At least one SVG exists for synthetic static/adaptive rows; static loss summary n=1 despite failed trial; outside-folder evidence rejected | Chart creation branch, selected failed exclusion, resolved-path containment | Visual accuracy, error bars, fair experiment design or network performance |
| `test_repository_audit` | Yes, recorded ok | `source_sha256` nonempty and routing_enabled key exists | Audit returns those structures for present files | Hashes matching an immutable original Git tree or correct runtime routing/ACL interpretation |

Run the existing suite when demonstrating or later changing code:

```powershell
python -B -m unittest discover -s monitoring/tests -v
```

Prerequisite: Python and existing source/config files. Reads test/evaluation source and core config; creates then removes synthetic temporary trial directories under `monitoring/tests`. `-B` prevents new bytecode writes. Expected success: eight named `... ok` lines, `Ran 8 tests`, `OK`; timing varies. Failure prints the failing assertion/exception. The earlier temporary-directory errors were resolved by using project-local temporary folders. Do not overwrite the historical transcript unintentionally; a future saved transcript should have a new name.

### 5.2 Software checks versus network checks

| Level | Available evidence | Status and boundary |
|---|---|---|
| Unit calculations/selected validation | Eight-test transcript and source assertions | Passed historically, with scope above |
| CSV/JSON/report generation | Actual readiness files parsed during this audit; 18 JSON/CSV rows, 162 summary records, input snapshot equality | Executed successfully for blocked input, not proof of every field/content on measured input |
| Audit CLI | Saved audit JSON and earlier command output | Executed static file/tool inspection |
| Capture CLI preflight | Saved missing-tool error | Executed failure path; no real capture |
| Actual host connectivity and leases | Member 1 prose PASS claims only; no corresponding supplied live environment/raw evidence | Not independently verified by Member 4 |
| ACL enforcement | No Member 2 security rules/applied SVI ACLs | Not tested; implementation absent in local package |
| Real project packet capture | No pcapng/pcap and no capture directory | Not performed |
| Automatic state transitions / effective quarantine | No engine or actual state logs; only manual CLI examples | Not tested; no implemented engine to exercise |
| Recovery / real detection-response timing | No matched condition/log/probe evidence | Not measured |
| Network latency/loss/goodput/disruption comparison | Saved metrics all null | No real comparison, graph or numerical result available |

Member 1's T12/T13 move tests say isolation/quarantine but describe lease changes and gateway pings. Even if those actions were reproduced, they would not establish denial of protected routed services. A static report is not a substitute for this acceptance test.

## 6. Missing components and integration contracts

### 6.1 Verified component state

| Component | Present, absent or incomplete? | Evidence and precise interpretation |
|---|---|---|
| Usable Packet Tracer topology | Absent from local folder/HEAD tree | No .pkt or equivalent runnable topology. Architecture and configuration text present. Cannot distinguish whether Member 1 has it elsewhere without asking them |
| Security policy | Requirements partially present; actual security implementation absent | MEMBER2_HANDOFF constrains placement/management/DHCP; no full allow/deny matrix, security ACL definitions or `ip access-group` in core export |
| Adaptive engine | Absent from local project | No executable engine, dependency/launch instructions, event API, detector, threshold implementation or recovery logic. VLAN move examples exist only as documentation |
| Monitoring/evaluation software | Present and independently usable offline | Source/tests/analysis work on recorded observations; not automatically attached to a live engine |
| Capture support | Wrapper present, external tool absent from historical PATH | Actual capture cannot be demonstrated from supplied evidence. PATH absence does not prove no installation anywhere on disk |
| Current running environment | Not established | No supplied start/status interface and no live network inspection was performed. Do not describe missing source as merely a stopped service |

The original handoff names POLICY-HOST as a Packet Tracer PC-PT. That label alone does not provide a normal host Python runtime or external SSH/network path into simulated switches. Member 3 must show the actual supported execution/control mechanism. It cannot be assumed that running Python on the laptop controls Packet Tracer ports. An emulated/physical alternative is acceptable only if documented and jointly approved as the actual environment, with the topology/security design preserved.

### 6.2 Required contracts and how Member 4 will use them

Artifact descriptions below marked **to be supplied** do not imply a particular unprovided filename or API already exists. Ask the responsible teammate for the real filenames and commands, then record them in the integrated handover.

| Contract | Current status | Owner / needed artifact | Interaction with existing Member 4 files | Acceptance / remaining integration |
|---|---|---|---|---|
| Topology/runtime/version | Missing executable topology; written design present | Member 1: `CN_Baseline_v1.pkt` named by original report, supported Packet Tracer version and startup/save steps | Enables all scenarios in scenarios.json; capture route depends on simulator versus real environment | Open topology without missing devices; run T1–T15 with new raw evidence |
| IP/VLAN/port inventory | Implemented as text; live values unconfirmed | Member 1: original configs/docs plus current DHCP/MAC-port map | Operator records actual source addresses and flow identity in observation notes | Match show vlan/trunk/route/binding output and actual endpoint configuration |
| Server/service health | Addresses/services described; instances unavailable | Member 1 with Member 2: .50.10/.11/.12/.13, .113.2 and enabled services/safe accounts if required | Supports authorized/protected/recovery/performance procedures | Authorized control host gets valid application response, not just ping |
| Credentials | Username admin described; passwords/key material unavailable/redacted | Members 1/2: safe local credentials and optional test accounts, delivered privately | capture/analysis do not consume credentials; operator/engine may need them | POLICY-HOST SSH .40.1/.21/.22 works; no secret appears in evidence |
| Access matrix and ACL text/attachment | Missing | Member 2: actual rule files, per-role/service/state outcomes, inbound core SVI bindings | Supplies expected outcomes currently provisional in scenarios.json and notes | Every allow/deny case verified with actual service request, management and DHCP preserved |
| Engine start/stop/status and dependencies | Missing | Member 3: actual engine source, config and launch/control procedure | No current automatic caller in evaluate.py; operator collects its output | Demonstrate actual supported switch control from runtime; no guessed command |
| State machine and thresholds | Requested state names exist in brief; implementation missing | Member 3: NORMAL/RESTRICTED/QUARANTINED transitions, counted event definition, cadence/window, escalation, reset/recovery rules | violations/recovery procedures depend on those exact definitions | Repeat threshold boundary tests; reset between trials; no ML component is required |
| Event identity and format | Missing | Member 3: original logs with actual schema, device/port/correlation IDs, occurrence/detection/decision/enforcement/recovery timestamps | Manually normalize relevant values to current observation schema, retaining originals | Trace one normalized row back to original log and correct host across IP changes |
| Clock domain/resolution | Missing for live components; current readiness UTC timestamps present | Members 1/3/4: declared simulation clock or synchronized wall clocks, precision/poll/probe intervals | evaluate.py only subtracts supplied timezone-aware timestamps | Verify comparable domain, ordering and uncertainty manually; no mixed clock subtraction |
| Effective restriction evidence | Missing | Members 2/3/4: switch acknowledgment plus last success/first attributable denied probe, healthy control host, DHCP lease | Becomes effective_denial_at and evidence links; not engine log alone | Protected service denied while intended remediation/control traffic behaves per matrix |
| Effective recovery evidence | Missing | Members 3/4: actual recovery condition plus NORMAL/port/lease and first restored approved service | Becomes recovery_condition_at/restored_at and evidence | Restore permitted access, validate remaining denials and no unrelated-host outage |
| Capture visibility | Points specified; access/mirroring not implemented here | Member 1: simulation evidence process or dedicated real mirror/capture interface and actual config | README procedures or capture.py, respectively | Observe the known request/reply at intended link; no unrelated host traffic |
| Observation importer | Implemented offline contract | Member 4: evaluate.py schema in Part 4 | Existing analyze command consumes normalized rows/evidence | Same trial regenerates same metrics; evidence attribution reviewed by team |

No automatic Member 3 integration exists today. Even after receiving an engine, Member 4 can use the current manual normalization workflow; an automated parser would be a separate future implementation decision requiring the real log schema first. The hard-coded audit/readiness limitations must be reviewed before relying on those modes after integration.

## 7. Complete architecture and experiment sequence

### 7.1 Planned data and control flow

```text
                          INTERNET-SRV 203.0.113.2
                                   |
                     EDGE-R Gi0/1 203.0.113.1 (PAT outside)
                     EDGE-R Gi0/0 10.0.0.2 (PAT inside)
                                   |
                         CORE-SW Fa0/24 10.0.0.1
                    [SVIs / DHCP / inter-VLAN routing]     Member 1
                    [inbound security ACLs: missing]       Member 2
                          /                       \
                    Gi0/1 trunk               Gi0/2 trunk
                         /                         \
                 ACCESS-SW-A                    ACCESS-SW-B
          students / faculty / admin       researchers / server VLAN 50
          PC-STU2 at Fa0/2                  .10 research, .11 DB,
          POLICY-HOST .40.50                .12 admin, .13 remediation

  Test requests ─> actual forwarding / routing / security decisions ─> service result
       |                              |
       |                         observed condition
       |                              v
       |                 Member 3 engine [missing]
       |                 detect -> decide -> switchport VLAN command
       |                            NORMAL <-> RESTRICTED / QUARANTINED
       |                              |
       |                     DHCP/port/ACL effects -> new service result
       v                              v
  Member 4: PDU/capture evidence + actual logs + matched request outcomes
       └─> normalized trial JSON -> evaluate.py -> CSV/JSON/report/SVG
```

Data flow is the student's HTTP/ICMP/etc. traffic through switches and routes. Control flow is the engine recognizing events and changing the offending port. Monitoring observes both; it does not itself implement routing, ACLs or policy state. The exact recovery edges and timing are to be supplied by Member 3; the diagram depicts intended behavior, not implemented code.

### 7.2 One complete experiment, after dependencies arrive

1. **Establish the environment.** Open the real supplied .pkt in the confirmed application version, or start the team's actual documented equivalent. There is no provided command to start an engine/network now. Preserve the original copy and save a run-specific local copy.
2. **Verify architecture first.** Follow `docs/08_verification_matrix.md`. On switches run `show vlan brief`, on core `show interfaces trunk`, `show ip interface brief`, `show ip route` and `show ip dhcp binding`; on edge inspect `show ip route` and `show ip nat translations`. Retain actual output. On PCs inspect `ipconfig` and gateway/server pings.
3. **Verify services and management.** From POLICY-HOST use the documented `ssh -l admin 192.168.40.1` (and .21/.22) with real local credentials. From a legitimate simulated client open the intended HTTP service. Use .113.2 and www.example.com only inside the intended simulated network. Archive health checks.
4. **Create the static-security comparator.** Apply Member 2's actual supplied rules to the documented inbound SVIs, not EDGE-R's NAT ACL. Record exact rule text and active bindings. Disable engine using Member 3's actual instructions. Verify allow/deny cases, including DHCP and management. Merely copying a rule file is not applied-state proof.
5. **Declare a trial.** Record configuration, scenario, trial ID, source lease/port, destination/service, expected result, clock domain, probe/request cadence, warm-up and measurement windows. Make a fresh evidence directory manually and preserve original logs.
6. **Run static traffic and collect observations.** Execute the selected scenario from its named PC. Capture simulation events or project-only real packets as appropriate. Record legitimate requests and protected attempts. Static prevention can already deny protected requests; note this as intended, not an adaptive transition.
7. **Reset and enable adaptive.** Use the same topology, services, ACLs and workload; restore normal port/lease and engine counters per supplied procedure. Start the real engine; confirm supported switch control. Preserve the engine configuration.
8. **Generate the defined trigger.** Follow the real threshold/window definition, not an invented number. Save occurrence/detection/decision/application logs. Record device identity across changed DHCP addresses. Keep a simultaneous unaffected authorized traffic stream.
9. **Verify effective restriction and quarantine.** Inspect changed access VLAN/lease and probe matrix-denied/allowed services. Confirm server health from the control host. Correlate last successful and first denied protected request with actual rule/port effects. Save all steps; a state variable is insufficient.
10. **Verify recovery.** Apply the actual condition, inspect restored state/VLAN/lease, issue `ipconfig /renew` if required by the documented environment and record first restored approved request. Verify unrelated traffic and remaining protected rules too.
11. **Repeat fairly.** Use identical counts/cadence/size/service warm-up and capture points; at least three trials when practical. Reset state/leases/counters and control background load. Label manual versus automatic intervention and any simulator time.
12. **Normalize and analyze.** Populate genuine observations JSON with evidence references; run the existing analyze command. Inspect validation failures, CSV/JSON, n values and charts; recompute a sample manually. Hand over input, evidence, output, configuration and limitations together.

### 7.3 Show actual access change, not a log change

For one identified host and service, retain evidence in this order: normal allowed request (where matrix allows it), violation/trigger, engine detection, actual port/policy acknowledgment, post-change protected denial attributable to enforcement, permitted remediation/control request, recovery condition, restored approved request. If the original static ACL always denies the selected protected flow, that flow cannot show a before-allowed/after-denied adaptive change; choose an additional matrix-approved normal permission that is intentionally revoked by restriction. Member 2 must define that permission rather than changing policy just to demonstrate success.

Show a control host still successfully accessing the same server. This helps distinguish policy enforcement from server failure or a broken link. A single timeout is ambiguous without supporting evidence. A tagged packet on VLAN70, a DHCP lease, or a QUARANTINED log line establishes only one part of the chain. HTTP success is not the same as ping success; verify the actual protected service.

### 7.4 Fair baseline comparison

| Configuration label accepted by code | Intended setup | Meaning |
|---|---|---|
| architecture_baseline | Current Member 1 design, no security ACLs, no engine | Useful architecture reachability reference; not the secure static comparator |
| static | Same topology + Member 2 ACLs, engine disabled | Conventional security baseline for requested comparison |
| adaptive | Same topology + same static ACLs + Member 3 engine | Incremental adaptive behavior and legitimate-traffic cost |

Compare security response and allowed-service availability under equal workload. A static ACL that blocks a prohibited request immediately is useful security behavior; it need not produce a detection event. Adaptive containment should demonstrate the additional intended change, such as broader restrictions following repeated violations, and any collateral disruption. Keep simulator versus wall-clock results explicitly separate. Do not treat Member 1 handoff's 1–3 ms claim as measured baseline data. Throughput can remain unavailable when the environment cannot produce a valid byte/time transfer test; no iperf service/tool is supplied.

## 8. Exact handover checklist

Status refers to this local folder at inspection. **Required** means needed for source handover or a complete project, not a claim that an absent artifact was created. For unprovided teammate artifacts without an established filename, “filename not supplied” is intentional; confirm the real one rather than inventing it.

### A. Member 4 deliverables

| Artifact | Owner | Required? | Status / why needed | Acceptance test |
|---|---|---|---|---|
| `monitoring/evaluate.py` | Member 4 | Required | Present; offline audit/import/calculation/analysis | Existing eight tests; import reviewed genuine trial later |
| `monitoring/capture.py` | Member 4 | Required | Present; bounded capture wrapper, only missing-tool path exercised | Preflight evidence now; real scoped capture plus both return codes zero later |
| `monitoring/scenarios.json` | Member 4 | Required | Present; reproducible traffic procedures | All six IDs load; operator can perform each after expectations supplied |
| `monitoring/tests/test_evaluate.py` | Member 4 | Required | Present; synthetic software regression checks | Eight tests pass; disclose boundaries |
| `monitoring/README.md` | Member 4 | Required | Present; detailed operating guide | Commands map to actual code; read with qualifications in this document |
| `monitoring/requirements.txt` | Member 4 | Required | Present; dependency note, no pip packages | Python works; optional capture/runtime dependencies supplied separately |
| `README.md` navigation changes | Member 4 over inherited file | Required | Present; project entry point | Links resolve locally |
| `REPORT_MEMBER4.md` | Member 4 | Required | Present; honest implementation/status report | Evidence paths exist; no unmeasured success claims |
| `HANDOVER_AND_TECHNICAL_WALKTHROUGH.md` | Member 4 | Required | This document; architecture and maintenance handover | File inventory and statuses match local artifacts |
| `monitoring/test-results.txt` | Member 4 | Required useful evidence | Present historical record; software only | Eight named tests match source, transcript says OK |
| `monitoring/capture-preflight.txt` | Member 4 | Required useful evidence | Present limitation record | Clearly says no capture performed |
| `monitoring/results/20261018T102624Z-26207990/audit.json` | Member 4 | Required useful evidence | Present historic environment/file snapshot | Parse JSON and inspect checked_at/scope |
| `monitoring/results/20261018T102624Z-46c9c62f/availability.json` | Member 4 | Required context | Present 18 readiness entries | All blocked; no traffic claimed |
| Six files in `monitoring/results/20261018T102624Z-46c9c62f/20261018T102625Z-e561ed3d/`: `input.json`, `evidence_manifest.json`, `results.json`, `results.csv`, `summary.json`, `report.md` | Member 4 | Required reproducible readiness output | Present; preserve together with source | 18 results, 162 n=0 summaries, empty manifest, exact input snapshot |
| Both listed `__pycache__/*.pyc` files | Interpreter-generated | Optional; omit from submission | Regenerable caches, no evidence value | Source runs without handing over cache |
| Genuine observations, pcapng/PDU evidence and comparison SVGs | Member 4 after integration | Required where supported | Not available; cannot substitute readiness data | Metrics traceable to actual repeatable trials |

The complete Member 4 source handover is `monitoring/` plus the root README/report/walkthrough, excluding cache files if packaging manually. Include generated readiness outputs with the explicit blocked label. Share the inherited configuration/document package as project context too. No file has been sent to teammates by this task.

### B. Obtain from Member 1

| Artifact | Owner | Required? | Current status / purpose | Acceptance test |
|---|---|---|---|---|
| `CN_Baseline_v1.pkt` | Member 1 | Required unless a documented equivalent replaces it | Named in original docs, absent here; instantiates actual devices/links/services | Opens in supplied version; correct topology; fresh T1–T15 evidence |
| Packet Tracer version and open/save/start instructions (filename not supplied) | Member 1 | Required | Missing; reproducible runtime | Another teammate opens/runs same local copy |
| `configs/*.cfg` — all seven exact files in Part 3 | Member 1 | Required | Already present; phase setup | Apply to matching lab devices; inspect saved active configuration |
| `running-configs/*.txt` — all four exact files in Part 3, plus fresh actual snapshots after integration | Member 1 | Required | Original references present; fresh verified snapshots absent | Running/startup comparison and current device outputs |
| `docs/01_physical_topology.md`, `docs/07_end_devices_configuration.md`, `docs/08_verification_matrix.md`, `REPORT_MEMBER1.md` | Member 1 | Required | Present design; missing raw proof and minor model inconsistency | Confirm ports/model and complete blank matrix with evidence |
| Current DHCP/MAC/port map and safe local management credentials (artifact name not supplied) | Member 1 | Required | Live values/credentials unavailable | PC-STU2 identity verified; POLICY-HOST SSH works |
| Original report screenshots and designated capture visibility (filenames not supplied) | Member 1 | Required evidence/access | Screenshots referenced but absent; capture points only documented | Actual supplied screenshots trace to topology; known probe visible at intended point |

### C. Obtain from Member 2

| Artifact | Owner | Required? | Current status / purpose | Acceptance test |
|---|---|---|---|---|
| Role/state/service access matrix (filename not supplied) | Member 2 | Required | Missing; resolves authorized/protected/remediation expectations | Each tested flow has explicit expected allow/deny in normal/restricted/quarantined states |
| Actual inbound CORE-SW SVI security ACL configuration and attachment commands (filenames not supplied) | Member 2 | Required | Missing; handoff constraints alone are not rules | Active bindings and real application allow/deny cases; VLAN60/70 restrictions effective |
| Security test cases and expected outcomes (filename not supplied) | Member 2 | Required | Missing; prevents arbitrary expected behavior | Cross-reference scenario source/destination/port and actual results |
| DHCP, management and transit preservation rules within those ACLs | Member 2 | Required | Requirements present; applied rules missing | Lease renewal, POLICY-HOST SSH and intended simulated internet access survive |
| Separate firewall implementation (if actual design uses one; filename not supplied) | Member 2 | Conditional | No separate firewall platform present; do not invent one | Demonstrate actual rule placement/function only if used |
| Safe service test accounts (if FTP or authenticated tests require them) | Member 2 with Member 1 | Conditional | No credential artifact supplied | Valid control login/transfer; secrets excluded from public evidence |

### D. Obtain from Member 3

| Artifact | Owner | Required? | Current status / purpose | Acceptance test |
|---|---|---|---|---|
| Engine source, dependencies and actual configuration (filenames not supplied) | Member 3 | Required | Missing; no runnable adaptive behavior | Starts on documented supported runtime; deterministic tests and live demonstration |
| Start/stop/reset/status instructions and actual switch-control mechanism | Member 3 | Required | Missing; Packet Tracer PC label is insufficient | Correct offender port changed by engine, not manual operator impersonation |
| State/threshold/window/escalation/recovery specification and implementation | Member 3 | Required | Only intended names and move commands described | Boundary/repeat/reset/recovery cases reproduce stated transitions |
| Original event logs with schema, identity/correlation and timestamps | Member 3 | Required | Missing; detection and recovery timing inputs unavailable | Trace trigger→detection→action→effective access and recovery on same device |
| Enforcement acknowledgment and safe restore procedure | Member 3 | Required | Missing; separates decision from applied policy | Port state verified, DHCP and access probes confirm change/restoration |

### E. Joint integration deliverables

| Artifact | Owner | Required? | Current status / purpose | Acceptance test |
|---|---|---|---|---|
| Complete usable network + static/adaptive configuration copies (actual filenames to agree) | Members 1–3 | Required | Missing integrated runtime | Same topology/ACLs; engine-only difference demonstrated |
| Agreed scenario expectations and event-to-observation mapping | Members 2–4 | Required | Catalog/schema present; actual policy/log mapping pending | Each row correlates to named flow, raw log and expected outcome |
| Genuine observations input, e.g. documented `monitoring/observations.json` | Member 4 with Member 3 | Required | Filename documented, file absent | Valid structured import with real evidence, no synthetic numbers |
| Run-specific configuration snapshots, CLI/PDU/log evidence or pcapng + metadata | All, assembled by Member 4 | Required | No network evidence yet | Independent examiner can trace effective denial and recovery |
| Repeated-trial CSV/JSON, summaries, generated reports | Member 4 | Required | Software ready; readiness-only outputs present | Recompute metrics, check nulls/failed trials and sample sizes |
| `comparison-<index>.svg` in genuine analysis run | Member 4 | Conditional on comparable measurements | Generator present; network charts absent | At least two measured configurations with same metric/conditions; labels correct |
| Updated integrated evaluation report/runbook with actual launch commands | All, coordinated by Member 4 | Required | Existing reports document blockers only | Teammate reproduces entire experiment without guessed interfaces |
| Valid throughput measurement evidence | Members 1/4 | Conditional on actual environment support | Unavailable | Receiver-delivered byte count and duration; otherwise explicitly not measured |

Submit maintained source/documentation and useful evidence. Do not submit bytecode caches or deleted temporary synthetic fixtures as results. Readiness outputs are reproducible but valuable as historical limitation evidence; preserve their original timestamps rather than relabeling them as final experiments.

## 9. Practical demonstration

### 9.1 What you can demonstrate today

All commands below use the project root. Run these later as a demonstration; this documentation task did not regenerate outputs.

| Step | Prerequisites and exact action | Expected evidence | What to explain / honest limitation |
|---|---|---|---|
| 1. Show scope | Open this document, `REPORT_MEMBER4.md` and `monitoring/README.md` | Actual files and missing .pkt/engine explained | “My role measures network behavior. This package currently supports offline evidence analysis; full integration needs teammates' components.” |
| 2. Show provenance | `git status --short` and `git ls-tree -r --name-only HEAD` | Original 19 files; local monitoring/report additions; modified README | Git state distinguishes original package and local work; does not certify all remote activity |
| 3. Run software tests | `python -B -m unittest discover -s monitoring/tests -v` | Eight tests, OK, temporary fixtures only | “These verify calculation/import logic. They are not eight successful university-network tests.” |
| 4. Explain saved limitation evidence | Open `monitoring/capture-preflight.txt` and saved audit JSON in Part 3 | No .pkt, no core ACL attachment, missing tools in historic audit | Tool-path absence is historic environment evidence; do not claim exhaustive installation discovery |
| 5. Generate a fresh audit | `python -B monitoring/evaluate.py audit` | Printed new folder and audit.json | Static file/tool inspection, not a topology launch; hard-coded messages require review after integration |
| 6. Regenerate saved readiness analysis | `python -B monitoring/evaluate.py analyze --input 'monitoring/results/20261018T102624Z-46c9c62f/availability.json'` | New results CSV/JSON, n=0 summaries/report; no comparison charts | “All 18 entries are blocked; blanks are missing measurements, not zero loss/instant detection.” |
| 7. Trace calculations | Open `monitoring/tests/test_evaluate.py`, inspect test_metrics and test_recovery | Expected synthetic arithmetic assertions | Clearly call numbers synthetic test inputs. No fabricated observations file or measured chart is used |

No actual capture interface is available in the supplied project. Do not show Wireshark capturing unrelated laptop traffic as evidence of these VLAN scenarios. No genuine graph demonstration is possible from blocked data; the chart branch is tested with temporary synthetic fixtures only.

### 9.2 Demonstrations after teammates provide the missing components

| Demonstration | Prerequisites | Exact existing action or command | Evidence and examiner explanation |
|---|---|---|---|
| Architecture reachability | Member 1 .pkt/version, configured devices/services | Open .pkt using Packet Tracer; simulated PC-RES1 Command Prompt: `ping 192.168.50.10`; inspect core with `show ip route`/`show ip dhcp binding` | Actual lease/routes/replies; this shows routing, not HTTP policy |
| Static security | Member 2 active SVI ACLs and matrix, healthy control host | In named simulated PCs use Browser `http://192.168.50.10` and `http://192.168.50.12` as matrix specifies | Expected/observed authorized and prohibited requests plus rule attachment; no guessed protected designation |
| Manual segmentation only | Verified ACCESS-SW-A Fa0/2 target, saved original VLAN/lease | Follow handoff: `configure terminal`, `interface FastEthernet0/2`, `switchport access vlan 70`, `end`; on PC-STU2 `ipconfig /renew`; restore documented original VLAN10 afterward | Port/lease change and service probes; explicitly a manual move, not automatic detection or engine timing |
| Automatic adaptive restriction | Real Member 3 engine/runtime/start instructions and threshold contract | Use Member 3's supplied real start command (none exists now); perform violations scenario at its real cadence | Original logs plus applied port change and actual access restriction; no invented engine CLI |
| Recovery | Actual recovery condition/reset mechanism | Apply Member 3's real condition; `ipconfig /renew` when required; request matrix-approved restored HTTP service | First successful permitted request linked to recovery condition; state variable alone insufficient |
| Simulated packet evidence | Working Packet Tracer topology | Simulation mode → filter relevant events → run scenario → inspect/save PDU details | Packet-level simulated forwarding/denial evidence with clock; not a PCAP |
| Optional real-interface capture | Actual matching deployment, tshark/driver and verified interface | `tshark -D`, then the supported capture.py form in Part 4 with real ID | Genuine pcapng/logs/metadata; verify both capture and analysis status |
| Final comparison | Genuine recorded observations and retained evidence | `python -B monitoring/evaluate.py analyze --input monitoring/observations.json` | Per-trial CSV/JSON, sample counts, summaries, conditional charts; demonstrate fairness and uncertainty |

Manual configuration examples are documentation of the existing handoff, not actions taken during this task. Confirm host identity and original port/VLAN before any future demonstration; operate only on this lab environment.

## 10. Maintenance notes and next actions

### 10.1 Known implementation qualifications

These observations explain code that exists; no repairs or new features were made in this documentation task.

1. **Offline collection:** there is no automatic traffic generator, ping parser, engine log adapter or connectivity verifier. The procedures and observation schema provide a path for genuine evidence, with manual normalization still required.
2. **Readiness strings:** audit limitations and blocked notes are hard-coded. They do not automatically become accurate when another member adds files. Inspect actual integration before recording a new readiness status.
3. **Audit provenance:** hashes describe current scanned non-monitoring files, not necessarily only original Git files. Use Git history/diff to establish provenance. Earlier README language about hashing original files is a simplification.
4. **Timestamp input:** current Python 3.14.6 accepts the Z examples in tests. For Python 3.10, use explicit `+00:00` instead of assuming Z parsing works, or use the verified newer interpreter. Clock synchronization and complete chronological checks remain operator responsibilities.
5. **RTT null input:** omit rtt_ms or use []; explicit null is rejected. Censored `<1 ms` values need separate notes and careful interpretation of any partial-sample mean.
6. **Result validity:** evidence file existence/hashes do not prove content truth, policy attribution or fair workloads. Measured/failed classification is supplied by the operator; the importer does not compare actual outcomes to the expected-policy catalog.
7. **Summary weighting:** means are unweighted trial-level means. Failed rows are excluded; inspect their notes so exclusion does not conceal a systematic problem. Report failed trial counts separately in the final scientific discussion.
8. **Capture verification:** missing-tool path is verified; real-interface filters/process/statistics are not. Overall exit status alone does not prove successful statistics or meaningful packets. Review metadata and return codes.
9. **Evidence replay:** results input retains original evidence paths. For a moved project, use the manifest to restore/update those source-relative paths or retain the original input folder layout. The importer does not transparently remap input references to archived evidence copies.
10. **Simulator limits:** labels like POLICY-HOST and quarantine VLAN do not provide a runnable external control API or security by themselves. Confirm Member 3's actual runtime and Member 2's effective routing filters.

### 10.2 Exact next steps for team integration

1. Request Member 1's actual `CN_Baseline_v1.pkt`, application version, safe management access and fresh T1–T15 evidence. Confirm minor device-model inconsistency and live port/lease identities.
2. Request Member 2's real access matrix, actual ACL text and inbound SVI attachments, including permitted remediation/management/DHCP behavior. Verify static allow/deny service cases first.
3. Request Member 3's actual source/runtime/launch/reset procedure, state/threshold/recovery definitions and timestamped event schema. Require a demonstration that the engine controls the intended switchport in the selected environment.
4. Agree on one end-to-end trial with matched clock domain, known offender identity, healthy control host, real occurrence/detection/application/recovery evidence and service results.
5. Use existing manual observation normalization; run analyze on genuine input and independently recompute one row. Record any code integration still needed as future work rather than pretending an automatic adapter already exists.
6. Repeat static/adaptive trials with equal conditions. Retain configurations, input, raw evidence and generated summaries/charts; report limitations, failed trials and unsupported throughput explicitly.

**Current verification boundary:** software calculation/import tests and blocked readiness output are supported by local evidence. The complete adaptive network is not functionally verified. The existing project was kept unchanged during this documentation task apart from adding this walkthrough. No commit, push, upload, fork or publication was performed.
