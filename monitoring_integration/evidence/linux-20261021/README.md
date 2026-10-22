# Selected Linux evidence

These are unchanged, small JSON outputs copied from the genuine 21 October 2026
Linux run `results/live-20261021T101238Z-a2e776/` and software run
`results/test-20261021T101444Z-89bc3f94/`.

- `verified_summary.json`: 74 live access checks and measured static/adaptive means.
- `application_summary.json`: 67 protocol/transition assertions.
- `application_packet_evidence.json`: independent protocol frame counts.
- `verification_audit.json`: source/preservation checks and three trial pairs.
- `test_summary.json`: the historical 115-test software result.

They are evidence summaries, not substitutes for the complete raw run. The raw
captures, detailed logs, generated keys/passwords, root filesystem caches and
169-artifact run remain local and are excluded from publication. Some references
inside these unchanged JSON files therefore resolve only in the original local
run folder. The pending-clarification field about Cisco/Packet Tracer reflects
that older audit; current PT status is in `../../../packet_tracer/evidence/PT_VERIFICATION_REPORT.md`.

Linux observations must not be presented as Packet Tracer or physical Cisco
measurements. Current source software regressions were rerun during publication;
their output remains in the local ignored results directory.
