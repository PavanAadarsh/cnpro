# Member 4 completion verification — four final corrections

Updated locally 21 October 2026. All four requested corrections are implemented
and verified against the real isolated Linux network. This does not assert Cisco
hardware deployment or full recovery-hold expiry.

Publication note, 22 October 2026: this is the historical **Linux** completion
report. Packet Tracer is now a confirmed requirement and has its own implemented
manual demonstration, exports, screenshots and remaining limitations in
`../packet_tracer/evidence/PT_VERIFICATION_REPORT.md`. The pending-clarification
wording about Packet Tracer at the end of this historical report is superseded;
actual physical Cisco deployment is not claimed. The 30/120-minute expiry scope
remains pending clarification. Five selected historical JSON summaries are
included under `evidence/linux-20261021/`; detailed run folders cited below remain
local and ignored. These old JSON snapshots retain their original audit context.

| Correction | Status | Changed implementation and regressions |
|---|---|---|
| Administration diagnostic return traffic | Fixed and verified | `policy.py`, `effective/CORE-SW_security_acls.cfg`, `tests/test_runtime.py`, `live_regressions.py`: scoped echo replies to administration; Linux requires established conntrack state; successful three-probe administration exchanges to all three user roles; reverse initiation and unsolicited replies denied with positive receiver controls |
| Endpoint DNS | Fixed and verified | `lab_dhcp.sh`, `lab.py`, `application_services.py`, `tests/test_runtime.py`, `live_regressions.py`: DHCP option 6, isolated per-endpoint resolver files, genuine DNS service, default OS resolution and service access by hostname; remediation-only DNS while restricted, no routed DNS in quarantine, normal resolver restored after recovery |
| Genuine HTTPS and FTP | Fixed and verified | `application_services.py`, `lab.py`, `lab_bootstrap.sh`, `tests/test_applications.py`, `live_regressions.py`: real TLS with trusted local certificate and hostname verification; untrusted certificate rejected; authenticated FTP login/RETR, wrong-password and anonymous 530 rejection, actual advertised data port 20; allowed/denied role checks and containment/recovery checks |
| Current reproducible documentation | Fixed and verified against implementation/results | `README.md`, `POLICY_RESOLUTION.md`, this report: current dependencies, startup, commands, real service behavior, evidence and limitations; obsolete missing-input/no-observations/banner-only claims removed |

## Tests actually completed

- **115 software tests passed**, with zero failures/errors and no skipped tests:
  62 unchanged Member 3 source tests, eight original Member 4 tests and 45 integration
  tests. Includes real localhost TLS handshakes and certificate-rejection regressions;
  these remain separate from routed network results.
- **74/74 existing live access checks passed.** Four old generic TCP/20 checks were
  removed because a real passive FTP data listener exists only after PASV. They
  were replaced by authenticated FTP protocol and file-transfer checks, preserving
  the supplied TCP20/21 permission rules rather than keeping fake port-20 banners.
- **67/67 new live application/ICMP/transition assertions passed.** These include
  actual administration ping exchanges, solicited raw-reply receiver controls,
  unsolicited-reply denial, default DNS resolution, HTTP/HTTPS by hostname, TLS
  trust rejection, FTP 230/226 success and 530 failures, verified restricted and
  quarantine VLANs, DHCP resolver changes and manual recovery. FTP negative-login
  tests include wrong password followed by anonymous login; both require 530,
  never a mere connection failure. Some assertions check the same transaction's
  returned data/port, so this count is assertions, not unique network flows.
- **Three static/adaptive trial pairs** completed with real captures, 20 ICMP
  probes and one 1 MiB research HTTP transfer per trial. Automatic deny-counter
  detection restricted PC-STU2 in all three adaptive trials; one trial also
  escalated to quarantine. Each trial recovered through verified admin clear.
  Unaffected legitimate requests: 40/27/39/30/31/29, all successful.
- **63/63 software replay assertions** passed with explicitly fixture enforcement.
  Source/effective-policy audit completed; upstream-original discrepancies are
  distinguished from corrected local runtime behavior.
- Raw PCAP: **24,328 frames**, **564 DHCP frames**, **zero kernel buffer drops**.
  Independent packet inspection found TLS handshake records, DNS traffic, FTP
  230/530/226 responses and actual FTP data payloads. Counts on `any` include
  repeated observations and are not unique transaction or packet-loss counts.
- All **15 captured implementation hashes** match current Python implementation;
  **169 non-private artifacts** have SHA-256 entries. All 33 prepared teammate
  files match pinned Git blobs; all 39 original-folder files match their baseline.
  Shell working copies use LF. No files are staged; HEAD remains `6481843`.

| Mean per-trial metric | Static | Adaptive |
|---|---:|---:|
| ICMP RTT | 0.088 ms | 0.116 ms |
| ICMP loss | 0% | 0% |
| HTTP application goodput | 867.89 Mbps | 791.86 Mbps |
| Legitimate-request disruption | 0% | 0% |

These are virtual-network measurements with three repetitions, not physical line
rates or evidence of a general performance advantage. Timing includes scheduling,
DHCP renewal and probe timeouts. Per-trial results retain exact measured values.

## Evidence (paths relative to monitoring_integration/)

- Live run: `results/live-20261021T101238Z-a2e776/`.
- New regressions: `results/live-20261021T101238Z-a2e776/application_checks.json`, `application_summary.json`,
  `application_transitions.jsonl`, `application_state.json`, `application_events.json`.
- Genuine raw traffic: `results/live-20261021T101238Z-a2e776/pcap/all.pcap`; counters: `capture.log`;
  independent protocol counts: `application_packet_evidence.json`.
- Existing checks: `results/live-20261021T101238Z-a2e776/access_matrix.json`, `identity_spoof_guard.json`.
- Readbacks: `results/live-20261021T101238Z-a2e776/bridge_readbacks.jsonl`, `address_readbacks.jsonl`,
  `identity.jsonl`, `enforcement.jsonl`, DHCP logs and leases.
- Trials: `results/live-20261021T101238Z-a2e776/static-*/`, `adaptive-*/`, `results.json`, `detection.jsonl`.
- Effective policy: `results/live-20261021T101238Z-a2e776/effective.nft`, `configurations/`, `policy_decisions.json`.
- Analysis: `results/live-20261021T101238Z-a2e776/verified_summary.json`, `observations.json`,
  `analysis/20261021T101559Z-b01224c3/` (nine imported genuine observations).
- Provenance/cross-check: `results/live-20261021T101238Z-a2e776/environment.json`, `artifact_manifest.json`,
  `verification_audit.json`.
- Software: `results/test-20261021T101444Z-89bc3f94/test_summary.json`, `tests.txt`.
- Source/effective audit: `results/audit-20261021T101638Z-d0d54e01/`.
- Fixture replay: `results/replay-20261021T101640Z-d706205c/`.

Earlier failed/partial runs and the pre-fix snapshot remain preserved under
results/. They are not cited as passing evidence. The earlier 111-test/78-check
report is superseded by the counts and paths above.

## Security, preservation and remaining scope

FTP passwords and TLS keys are generated per live run in ignored `private-services/`.
No generated password or private-key content was found in changed source/docs or
textual run evidence. Raw FTP captures can contain the ephemeral password: do
not publish PCAPs, private-services, verbose logs, runtime caches, upstream copies
or their duplicated raw analysis inputs. All remain on this laptop.

Member 1 addressing/services, Member 2 ACL ownership and Member 3 policy logic
are preserved. This uses real Linux networking; the bridge backend replaces
Cisco SSH transport, not the engine. Administrative application transitions use
the actual engine's explicit enforcement interface; automatic detection is
separately verified in the three adaptive trial pairs.

**Pending clarification, excluded from this task's verdict:**

1. Cisco Packet Tracer implementation / actual Cisco device deployment. IOS needs
   a reviewed stateful return-path design; the intermediate stateless ACL snippet
   is not itself equivalent to Linux conntrack. No Cisco timing/deployment claim.
2. Full 30/120-minute automatic recovery expiry. Hold rules remain unchanged;
   software tests cover decisions, while live recovery here is administrative.

No other dependency remains for these four corrections in the chosen Linux lab.
No staging, commit, push, upload, branch creation or original-folder modification.
