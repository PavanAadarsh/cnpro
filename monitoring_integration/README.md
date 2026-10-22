# Member 4 integration: reproducible Linux network lab

For the confirmed Packet Tracer requirement, open the separate
[final topology and instructions](../packet_tracer/README.md). The current PT
implementation uses a controlled manual state demonstration; this Linux engine
does not automatically control Packet Tracer. Five selected historical Linux
evidence summaries are included under [evidence/linux-20261021](evidence/linux-20261021/README.md).

This add-on uses Member 1's VLANs, addressing, DHCP ranges and server roles,
Member 2's delivered ACLs, Member 3's actual policy engine/thresholds/recovery
logic, and Member 4's monitoring and analysis. Prepared teammate sources under
`upstream/` are unchanged copies of the Git commits pinned in `sources.json`.
`runtime.py` subclasses the engine to verify real enforcement and recovery;
`policy.py` reconciles the documented security requirements and compiles the
ACLs into installed kernel nftables rules. See `POLICY_RESOLUTION.md`.

## Prerequisites and startup

Run from the integrated repository root on this Windows laptop, using Python 3
and Git. The loopback TLS software tests also need a host OpenSSL executable
(the installed Git for Windows executable is supported); localhost connections
must be permitted. The existing `docker-desktop` WSL distribution must run as root and
support network/mount namespaces, Linux VLAN bridges and inet/netdev nftables.
The Docker daemon is not used. No physical interface or Windows firewall is
reconfigured. The launcher uses an isolated network namespace and a private
384 MiB RAM-backed Alpine root. Allow additional disk space for captures and
analysis copies. Initial runtime preparation needs access to the official Alpine
package repository; the root archive is pinned and checksum-verified.

```powershell
# Materialize pinned dependencies if needed; requires their existing Git objects.
python -B monitoring_integration/prepare_upstream.py
# Software regressions (separate from network evidence):
python -B monitoring_integration/run.py test
# Software engine replay, with explicitly simulated enforcement:
python -B monitoring_integration/run.py replay --trials 3
# Real DHCP, VLANs, firewall, services, capture, regressions and three trial pairs:
python -B monitoring_integration/run.py live
# Inspect source contracts/effective policy and available completed live evidence:
python -B monitoring_integration/run.py audit
```

A ZIP download lacks dependency Git objects. If the pinned commits are unavailable,
obtain their histories before running dependency preparation. The existing local
checkout already has the required teammate inputs. No topology `.pkt` or extra
teammate implementation is needed for this Linux alternative. Do not edit the
prepared copies or publish them: upstream Member 3 sources include a lab password.
The preparation tool refuses unknown edits and does not change branches.

`prepare_lab.py` verifies/downloads Alpine; `lab_bootstrap.sh` prepares packages
and starts `lab.py` in isolation. Required packages are Python, iproute2, nftables,
tcpdump, dnsmasq, OpenSSL and pyftpdlib (iperf3 remains available but the measured
transfer uses the permitted research HTTP path). The application-enabled runtime
cache is separate from the earlier runtime cache; earlier evidence is preserved.

## Actual services and security behavior

- DHCP option 6 gives normal VLANs `203.0.113.2`, the supplied INTERNET-SRV DNS
  address. Restricted and quarantine leases receive `192.168.50.13`, the supplied
  remediation DNS address. Quarantine rules block routed DNS; no public/host
  resolver fallback is installed. `lab_dhcp.sh` updates each namespace's dedicated
  resolver file in place on lease acquisition/renewal.
- Real dnsmasq DNS serves the supplied `www.example.com -> 203.0.113.2` record.
  Normal DNS also maps lowercase existing device names `srv-research`, `srv-db`,
  `srv-admin`, `srv-remediate` to their documented server addresses. These are
  lab aliases for the supplied devices. Remediation DNS serves only its own name.
  Tests use the operating system resolver, without a DNS-server argument.
- Research/admin/internet HTTPS performs TLS 1.2 or later and returns HTTP 200.
  A per-run self-signed lab certificate includes matching hostname/IP SANs.
  Clients explicitly trust that certificate and verify hostnames; a negative
  trust test must reject it. This is local TLS verification, not public PKI.
- DB FTP uses pyftpdlib, a generated per-run password, no anonymous account,
  read-only authenticated access and an actual sample-file transfer. Passive
  data port 20 and control port 21 match the supplied ACL permissions. This
  deliberate lab port choice avoids opening an unrelated passive-port range.
  Wrong passwords must receive FTP 530; a timeout cannot pass that check.
- HTTP health endpoints on all server namespaces support controlled denial and
  recovery checks; the database's required application service is FTP. The
  internet port 25 banner and management port 22 listener remain explicitly
  transport-only instrumentation, not SMTP/Cisco SSH implementations.
- Administration pings to student/faculty/research endpoints receive replies.
  The effective ACL permits echo replies to the admin subnet only; the Linux
  rules additionally require established connection state. New user-to-admin
  pings and unsolicited echo replies remain blocked. This exception does not
  apply to restricted/quarantine VLANs.
- Containment uses real bridge PVID changes, DHCP renewal, current MAC/IP/port
  bindings, installed firewall rules and connectivity readbacks. Automatic
  detection reads actual per-endpoint kernel deny counters and passes events
  to the actual Member 3 engine. Identity does not assume particular DHCP IPs.

`live_regressions.py` verifies completed ICMP exchanges and negative access,
normal resolver use, HTTP/HTTPS by hostname, TLS trust rejection, FTP login and
file transfer, wrong-password rejection, restriction, quarantine and verified
manual recovery. `application_services.py` contains the actual application
servers/clients. The existing access matrix remains a separate transport/ICMP
check, not a substitute for the application checks.

## Evidence and interpretation

Every run gets a new ignored directory; failures remain marked failed and are
not treated as completion. `COMPLETION_REPORT.md` identifies the latest verified
runs and exact counts. Under `results/live-*/`:

- `status.json`, `access_matrix.json`: completion state and existing access checks.
- `application_checks.json`, `application_summary.json`: actual protocol and
  administration regression outcomes, timestamps, resolver/readback evidence.
- `application_transitions.jsonl`: actual engine-driven application containment
  and manual recovery. `bridge_readbacks.jsonl`, `address_readbacks.jsonl`,
  `identity.jsonl`, `enforcement.jsonl` and DHCP logs retain raw observations.
- `pcap/all.pcap`, `capture.log`: genuine traffic and tcpdump capture/drop counts.
- `effective.nft`, `configurations/`: generated and installed firewall snapshots.
- `static-*/`, `adaptive-*/`: three comparable paired trials, real 20-probe ping
  samples, 1 MiB HTTP transfers, legitimate-traffic logs and measured results.
- `detection.jsonl`, `adaptive-*/transitions.jsonl`: detection/decision/action.
- `verified_summary.json`, `observations.json`, `analysis/`: capture validation,
  genuine observations imported through the original Member 4 analyzer and its
  generated charts/tables. Throughput is virtual-network application goodput;
  three trials cannot establish a general adaptive speed advantage.
- `environment.json`: dependency versions, pinned sources, implementation hashes
  and separate host/experiment network namespace identifiers.

`results/test-*/tests.txt` and `test_summary.json` are software-only evidence.
`replay` uses recorded fixture enforcement, never live evidence. `contract_audit`
intentionally inspects upstream originals, so an upstream discrepancy does not
by itself describe the corrected runtime. Packet Tracer capture_points.json is
a separate simulator mapping, not Linux traffic through physical Cisco ports.

All results remain local and Git-ignored. **Do not publish raw PCAPs, private-services/,
FTP credential JSON, private keys, verbose logs, runtime caches or upstream copies.**
FTP is intentionally a plaintext lab protocol, so captures can contain its ephemeral
password. Keep only reviewed, credential-free summary evidence if publishing later.

## Pending clarification (excluded from current completion decision)

1. Packet Tracer implementation / actual Cisco device deployment. Linux results
   do not verify IOS behavior or Cisco timing. The IOS intermediate ACL snippet
   cannot itself supply Linux connection tracking; Cisco deployment needs a
   reviewed compatible stateful return-path design and device access.
2. Full 30/120-minute automatic recovery expiry. Hold rules are preserved and
   software-tested; short live runs verify administrative recovery, not expiry.
   A full-duration run with continuing DHCP renewal would be required if mandated.

These items are neither completed nor failed and await faculty/teammate clarification.
