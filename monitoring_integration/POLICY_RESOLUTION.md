# Effective local policy and deployment scope

This local integration resolves contradictory descriptions under the user's
instruction to implement the fixes. It does not claim external teammate approval.
The published teammate files remain immutable in upstream/. The actual Linux
rules are compiled from Member 2's ACLs by policy.py and archived with every run.

| Role/state | Permitted | Denied |
|---|---|---|
| Students | DHCP, own gateway ping, internet HTTP/HTTPS and DNS, public research HTTP, remediation HTTP/DNS | Admin/database services, other user subnets, management SSH |
| Faculty | Student essentials plus research HTTPS | Admin/database services, other user subnets, management SSH |
| Researchers | Essentials, research HTTP/HTTPS and benchmark ping, database TCP 20/21 | Administrative services and switch SSH |
| Administration | All campus server services and simulated-internet ports; administrative campus access | Management SSH unless from POLICY-HOST |
| Servers | Replies to established/related connections; DHCP where configured | New routed connections initiated toward user endpoints |
| Restricted | DHCP, own gateway ping, remediation HTTP and TCP/UDP DNS | Internet, other servers, peer subnets and SSH |
| Quarantine | DHCP and own gateway ping | All routed server, user-subnet, internet and SSH access |

Same-VLAN traffic is switched at layer 2, as in Member 1's architecture. VLAN50
does not provide private isolation between servers. Linux ingress MAC/IP/port
guards prevent one endpoint impersonating another. The dedicated management
input filter permits TCP22 only from POLICY-HOST; the lab does not emulate IOS
authentication or claim that a TCP listener is a Cisco SSH switch.

## Disagreements resolved

1. Member 2's early unrestricted ICMP rules bypassed later student peer/admin
   and faculty/research administrative denials. Diagnostics are now limited to
   the documented gateways and research performance target. Administration-initiated
   echo replies to VLAN40 are explicitly retained; Linux also requires established
   conntrack state. User-initiated administration access remains denied.
2. The admin matrix permits all internet ports but the old ACL allowed only
   web/DNS. The effective rule honors the matrix for INTERNET-SRV, without
   broadening other roles.
3. Member 2 requires restricted devices to have no internet, while Member 3
   permits restricted web/DNS externally. The stricter security-owner policy
   takes precedence; restricted remediation HTTP/DNS remains available.
4. Member 3 permits quarantine remediation HTTP/ICMP; Member 2 explicitly requires
   total server isolation. The latter is retained. Restricted remediation ICMP
   is also denied; its allowed services are HTTP and DNS.
5. The shorthand 'quarantine DHCP only/zero routed traffic' omitted gateway ping.
   The detailed Member 2 matrix, ACL and Member 3 matrix agree on gateway ping;
   that explicit exception is retained.
6. Member 3's 'all normal peers denied' description omitted Member 2's admin
   maintenance exception. Administrative privileges remain explicit exceptions.
7. General admin SSH permission conflicted with the designated POLICY-HOST and
   VTY access-class restriction. Only the designated host may reach management.
   An SVI ACL alone cannot protect same-VLAN switch management.
8. VLAN50's broad permit ip allowed arbitrary server initiation despite its
   response-only description. The Linux deployment enforces real conntrack reply
   state. The effective IOS snippet is an intermediate stateless translation;
   its ACK checks are not a stateful firewall, and it is not a verified IOS
   deployment equivalent. Hardware deployment needs an appropriate stateful
   feature or separately reviewed server egress policy.
9. Original UDP destination-only DHCP permits allowed unrelated source ports.
   The translated ACLs now constrain the DHCP client/server source ports too.
10. Original snapshots/report PASS labels, arbitrary DHCP .100/.101 assumptions,
    and sample CLI transcripts are not live proof. Tests use the actual current
    leases, MACs, port PVIDs, service controls and captured traffic.

## Reproduce

From the existing integrated project folder on this laptop:

```powershell
python -B monitoring_integration/prepare_upstream.py
python -B monitoring_integration/run.py test
python -B monitoring_integration/run.py replay --trials 3
python -B monitoring_integration/run.py live
python -B monitoring_integration/run.py audit
```

The live command uses the installed docker-desktop WSL distribution, not the
broken Docker daemon. A pinned official Alpine runtime is downloaded and
checksum-verified. Tools execute in private RAM-backed mounts and a fresh
network namespace; the Windows firewall, routes and physical interfaces are not
changed. All generated evidence stays in results/live-*/. No Docker reset,
branch change, upload or publication is required.

The source engine's real thresholds and 30/120-minute hold rules are preserved.
The short live experiments measure administrative recovery, not full-length
automatic hold expiry. Unit tests cover the hold and failure paths; extended
automatic recovery timing and real IOS/SSH deployment require separate runs.
Throughput is application HTTP goodput over a virtual Linux network. The current
lab implements real HTTPS and authenticated FTP transfers on the supplied ports.
See README.md and COMPLETION_REPORT.md for protocol evidence and safe local
credential handling. Cisco deployment and full automatic expiry are pending
clarification and excluded from the current completion decision.
