# Final local handoff

Generated without screen control. 21 devices, 27 links;
cabled switch ports checked against the genuine exports.

136/136 initial-flow configuration expectations match.
These are offline inferences, not additional live test passes. Existing observed
results are recorded separately in ../evidence/observed_test_results.csv.

## Gateway correction status

The current EDGE-R export contains the applied QUARANTINE-IN-V2 binding
and permits the agreed own-gateway echo. The user also supplied successful
gateway/blocked-server ping screenshots and reported saving the topology.

The retained pending_changes directory contains the reference correction and
historical rollback, not a request to reapply the completed change. Rollback
restores the former gateway-ping denial. Review current exports before use.

## Remaining simulator work

- Active FTP retrieval and denied upload now have user screenshot evidence.
  Delete/rename denial still requires disposable fixtures. Passive FTP remains unresolved.
- The user reports removal of the default full-permission FTP account and a saved
  topology. This server-account state is not independently decoded from the .pkt.
- Management SVI reachability and unused server-service inventory are unverified.
- Automatic PT detection/control, full recovery expiry and PT performance comparison
  remain unimplemented or unverified. Existing Linux evidence is separate.

Follow ../README.md for endpoint services/DNS and manual build steps. Use the
seven genuine exports referenced by topology.json; avoid older candidate scripts.
No FTP password is generated or copied into this package.
