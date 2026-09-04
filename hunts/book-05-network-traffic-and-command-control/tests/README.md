# Test contract

The executable test suite lives in `book05_lab/verify.py` so the reader has one
entry point rather than a second test runner to configure. For every H01–H24
listing it runs four isolated scopes:

1. positive cohort: exact golden entity set must appear;
2. negative cohort: no result may appear;
3. edge cohort: no detection may appear (H12 also asserts the partial-capture
   adequacy facts separately); and
4. full fixture: exact combined golden entity set and hunt-specific sufficient
   statistics must match.

The suite also checks deterministic regeneration, per-file SHA-256 values,
schema and exhaustive analytic-consumed raw/canonical lineage, query ground-truth isolation, PCAP structure,
version locks, actual Zeek/Suricata replay, and H12 cross-sensor packet parity.
Results are written to `reports/verification.json`, `reports/junit.xml`, and
`reports/results/hunt_XX.json`.
