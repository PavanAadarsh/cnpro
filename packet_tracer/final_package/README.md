# Final local handoff

Generated without screen control. 21 devices, 27 links;
cabled switch ports checked against the genuine exports.

135/136 initial-flow configuration expectations match.
These are offline inferences, not additional live test passes. Existing observed
results remain in ../evidence/observed_test_results.csv and were not rewritten.

## Pending configuration correction

Quarantine currently denies its own gateway ping, contrary to the detailed agreed
policy. pending_changes/EDGE-R_quarantine_gateway.cfg prepares a replacement ACL
that adds only echo to 192.168.70.1 from 192.168.70.0/24. DHCP and all routed-server
denials remain. EDGE-R_rollback.cfg restores the original binding. Neither file
has been applied to Packet Tracer. A new export and saved topology are required
after any manual application; rebuild this package from the new export then.

## Remaining simulator work

- Apply that correction and check gateway ping plus continued server denial.
- FTP retrieval and denied write/delete/rename behaviour: use disposable fixtures;
  active listing already has user evidence. Passive FTP remains unresolved.
- Management SVI reachability and unused server-service inventory are unverified.
- Automatic PT detection/control, full recovery expiry and PT performance comparison
  remain unimplemented or unverified. Existing Linux evidence is separate.

Follow ../README.md for endpoint services/DNS and manual build steps. Use the
seven genuine exports referenced by topology.json; avoid older candidate scripts.
No FTP password is generated or copied into this package.
