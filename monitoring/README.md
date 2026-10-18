# Member 4: Monitoring and evaluation

Run all commands from the repository root. Python 3.10+; no pip packages required.
Optional real-interface captures require Wireshark/tshark and a working capture driver
(Npcap on Windows), with permission to capture. Packet Tracer requires a separately
installed Cisco Packet Tracer application and the missing topology file.

```
python -m unittest discover -s monitoring/tests -v
python monitoring/evaluate.py audit
python monitoring/evaluate.py blocked
python monitoring/evaluate.py analyze --input monitoring/observations.json
```

The last command requires genuine observations you have collected, following the
schema below; no fabricated example dataset is supplied. `blocked` records an
availability check, not traffic results. Every command creates a unique run folder.
The audit hashes the original source files. No script writes switch configuration,
sends traffic from the laptop, alters routing, or contacts a remote service.

## Inventory and integration

Inspected source: branch `member1-network-architecture`, commit
`e866597362d03cb4eda2e2dbb80a7c7f759cdb6f`.
Original repository has 19 files: README, Member 1 report, seven configuration
snippets, four running configurations, three handoffs, and three topology/host/test
documents. No source engine, tests, captures, logs, or `.pkt` file was supplied.
Member 1's historical PASS labels and timing estimates are not independently
measured evidence for this evaluation. Original files are preserved except the
README link added for navigation.

Member 2 must supply the access matrix and inbound CORE-SW SVI ACLs, including
VLANs 60/70, DHCP preservation, and POLICY-HOST SSH access. EDGE-R ACL 1 is NAT
classification and must remain unchanged. Member 3 must supply the executable
engine, trigger thresholds, event/log format, polling interval, recovery condition,
and enforcement acknowledgments. NORMAL/RESTRICTED/QUARANTINED are requested
states; this branch only documents VLAN 10/60/70 moves, not implemented states.
There is no real event API to integrate with yet. The observation schema is an
offline evidence adapter, not a replacement policy engine. Preserve original logs
alongside the normalized observations once those components exist.

## Reproduce traffic in Packet Tracer

1. Obtain `CN_Baseline_v1.pkt` from Member 1. If unavailable, build the exact device
   and cable layout in `docs/01_physical_topology.md`, apply `configs` in phase
   order, configure end devices per `docs/07_end_devices_configuration.md`, then
   run T1–T15. Keep a new local project copy. Credentials are placeholders and
   must be supplied locally; do not include passwords in evidence.
2. Save three independent configuration copies: `architecture_baseline` (current
   no-ACL branch), `static` (Member 2 ACLs, engine disabled), and `adaptive` (same
   ACLs and topology, engine enabled). A no-ACL baseline is not the requested
   conventional static-security comparator. Do not conflate these configurations.
3. Follow `monitoring/scenarios.json`. Source is the named simulated PC, not the
   laptop. Record actual DHCP addresses using `ipconfig` and CORE-SW bindings;
   never assume PC-STU2 is .101. Confirm policy expectations with Member 2 first.
4. Warm up ARP/DNS identically, then perform at least 3 trials per configuration
   with 20 ICMP probes and the same request schedule, sizes, and duration.
   Reset engine state and renew the offender lease between trials. Save configuration
   snapshots, state logs, CLI transcripts, simulation event details and screenshots
   under a fresh trial folder. Observe expected AND actual outcome for each request.
5. For transition tests record the first condition, detection, switch acknowledgment,
   last successful protected request, first denied protected request, recovery
   condition, first restored permitted request, and unaffected host requests.
   A VLAN/state log alone proves no effective isolation. Verify service denial,
   remediation access and unrelated authorized traffic separately. Confirm a denied
   service is healthy from an authorized control host to avoid confusing outage
   with successful enforcement. Distinguish ACL denial from timeout/unknown causes.
6. Save the original and changed switchport output plus DHCP lease. Any manual
   Fa0/2 VLAN 10→60→70→10 exercise follows Member 3 handoff but must be labeled
   manual, not automatic detection or policy-response measurement.

## Capture workflow

Packet Tracer traffic does not traverse Windows network adapters. Wireshark on
the laptop cannot capture those simulated packets. Use Simulation mode, filter
ARP/ICMP/TCP/HTTP/DHCP as appropriate, clear old events, execute the scenario,
and save event-list screenshots and inbound/outbound PDU details. Retain the
simulation clock and .pkt copy with the evidence. Do not label screenshots PCAPs.
No PCAP export or programmatic Packet Tracer control is assumed.

For a separately available authorized physical/emulated deployment only, mirror
CORE-SW Gi0/1 (VLANs 10/20/40), Gi0/2 (30/50), or Fa0/24 (transit) to a dedicated
capture interface, if that platform supports mirroring. Confirm the interface sees
only this project and record the mirror configuration. Do not repurpose active
ports without checking their impact. List capture interfaces and run a bounded capture:

```
tshark -D
python monitoring/capture.py --interface PROJECT_INTERFACE --project-only --configuration static --scenario performance --seconds 30 --tagged
```

Replace PROJECT_INTERFACE with the verified interface ID. Omit `--tagged` on an
untagged access/transit interface. Capture stops after the duration or 10 MB;
only the created subprocess is subject to timeout cleanup. No unrelated process
is stopped. Interrupted/error captures are marked in metadata and require review.
Capture filter covers documented campus, transit and simulated-internet subnets;
128-byte snapshots limit payload exposure but may still contain sensitive data.
Do not use a shared host interface merely because its addresses match this filter.

Open resulting pcapng in Wireshark; useful display filters:
`icmp`, `dhcp`, `http`, `vlan.id == 60`, `ip.addr == 192.168.50.12`.
For a saved capture use:

```
tshark -r PATH_TO_CAPTURE -q -z io,stat,1
tshark -r PATH_TO_CAPTURE -Y icmp -T fields -e frame.time_epoch -e ip.src -e ip.dst -e icmp.type -e icmp.seq
```

Frame counts are observations at one capture point, not delivered goodput or
end-to-end packet loss. Never infer application success from SYN or VLAN tags.

## Observation input and evidence

Create a JSON array, one object per scenario/configuration/trial. Required keys:
`scenario` (scenario ID), `configuration` (`architecture_baseline`, `static`,
`adaptive`), positive integer `trial`, `start_at`, `end_at` (ISO8601 with timezone),
`status` (`measured`, `failed`, `blocked`), `notes` (expected/observed outcome,
source address, destination, protocol, clock domain, timing resolution, errors).
Executed trials also require `evidence`: a list of real relative file paths inside
the input JSON folder. Import copies these files and records SHA256 hashes.
Keep originals with the input JSON if you want to rerun the original import;
the saved manifest maps original files to archived copies.

Optional keys, absent or null when unavailable:

| Keys | Meaning |
|---|---|
| condition_at, detected_at | First defined condition and actual detection |
| effective_denial_at | First failed protected request attributable to enforcement |
| recovery_condition_at, restored_at | Defined recovery condition and first restored permitted request |
| probes_sent, probes_received | ICMP requests and matched replies in the trial |
| rtt_ms | Individual displayed/measured successful ICMP RTTs, in ms |
| legitimate_attempted, legitimate_succeeded | Authorized application requests and verified responses |
| unauthorized_attempted, unauthorized_succeeded | Matrix-denied application requests and actual successful responses |
| transition_attempted, transition_succeeded | Authorized requests in the explicitly defined transition window |
| transferred_bytes, transfer_seconds | Successfully delivered application bytes and elapsed seconds |

All timestamp pairs must share a synchronized clock domain and describe the same
device and transition. Use separate rows/scenario IDs for restriction and quarantine
or different recovery steps. Retain raw timestamps for all steps in the evidence.
Packet Tracer simulation times may be normalized to a declared fixed epoch with
UTC offset, explicitly labeling simulated time in notes. Never mix wall time and
simulation time. A displayed `<1 ms` RTT is censored, not a measured zero: leave it
out of numeric samples and record its count/range in notes. Do not convert missing
event logs to zero detection time. Failed/incomplete experiments use `failed` and
are retained but excluded from summaries. Properly executed probes with 100% loss
are `measured`, with notes explaining whether this matches the expected outcome.

## Metrics and analysis

Detection = detected minus condition; response = first effective denial minus
detection; recovery = restored permitted connectivity minus recovery condition.
Units are milliseconds. Response is an observed upper bound at the probe cadence,
not the precise switch commit instant. A one-second probe cadence adds up to one
second uncertainty; include detection poll interval, clock skew and DHCP renewal
delay in notes. State-change logging without service evidence cannot establish
these response/recovery times.

Latency = mean successful RTT with sample count. Loss = (sent−received)/sent×100.
Throughput = delivered bytes×8/seconds/1e6, Mbps; no throughput measurement is
available from this Packet Tracer branch. Use a real approved application transfer
and receiver byte counts if the deployed environment later supports it; no iperf
service is assumed on Server-PT. Disruption = failed authorized transition-window
requests/attempts×100. Connection success = successful authorized application
requests/attempts×100; unauthorized success is reported separately. Zero attempts
produce null, never a zero percent failure. All counters describe one trial/window.

Outputs: input snapshot, evidence manifest/copies, results CSV/JSON, summary JSON,
and Markdown tables. Summaries group scenario/configuration and report n, mean,
median, minimum and maximum of available measured trials, not pooled rates.
SVG comparison charts are emitted only when at least two configurations have
measured values for the same scenario/metric. Chart units are in metric names;
there are no charts for blocked trials. These scripts validate structure and
calculations; the operator must establish truth and attribution from raw evidence.
