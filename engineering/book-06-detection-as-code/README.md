# Detection Factory — Book 6

Companion to Grant Halden, *Practical Threat Hunting: Detection Engineering and Detection-as-Code*.

This directory is one cumulative reference implementation with four small synthetic logic classes, 24 chapter guides, explicit fixture expectations, native candidate queries, disabled platform resources, and local evidence. It is not a production detection pack.

## Start

Use Python 3.12 (edition tested with 3.12.14). The offline core has no third-party dependencies and no network activity.

```sh
python tooling/factory.py validate
python tooling/factory.py run single-positive
python tooling/factory.py mutate
python tooling/controls.py
python tooling/factory.py metrics
```

All 58 authored behavioral cases and 12 minimum contract checks passed in the edition build. The nine reference mutation operators were killed. Re-run locally rather than trusting those counts alone. Results appear under build/ and do not alter canonical fixtures.

## Evidence boundary

Python evaluates the reference contract; it does not execute KQL or SPL. Native KQL, native SPL, Sentinel rule execution, Splunk Enterprise Security finding materialization, scheduled replay, and production deployment were NOT RUN/BLOCKED in the authoring environment. Platform resources are disabled. Do not enable them until their declared normalization, scheduling, native conformance, output, performance, health, and rollback checks pass in an explicitly authorized lab.

KQL target: Sentinel scheduled analytics, custom DetectionEvents_CL, ARM API 2025-09-01. SPL target: Splunk Enterprise 10.4 raw indexed source; ES 8.6 consumer integration requires separate native configuration and proof. No CIM acceleration is claimed.

## Layout

- detections/DET-001 through DET-004: intake, contracts, Sigma decisions, KQL/SPL candidates, fixtures references, alert interface, disabled resources.
- tooling/: offline reference, control tests, fixture export and native result comparison.
- fixtures/: canonical corpus and manifest; expected outputs are independently authored.
- schemas/, enrichments/, catalog/: data and ownership contracts.
- ci/, deploy/: candidate conversion, workflow references, disabled delivery plans.
- metrics/: disclosed metric and feedback data.
- docs/chapters/: 24 cumulative guides, review questions, and exercise answer criteria.
- docs/evidence/: edition results and limitations.

Start from the immutable edition commit linked in book/detection-engineering-and-detection-as-code.md. Chapter checkpoint manifests identify cumulative study scope within that edition; they are not claims of 24 historical release tags. Work in your own local branch. External pull requests remain governed by the series CONTRIBUTING.md.

Only inert synthetic data is included. No live credentials, customer telemetry, malware, or offensive actions are required. The lab defaults to local evaluation and dry-run planning. A native platform may require separately authorized resources, costs, and license acceptance; no script accepts terms on your behalf.

Corrections: use the series issue templates and include the book chapter, detection version, case ID, command, target version, and a sanitized minimal reproduction. Never post secrets or raw organizational logs.

## Reproduce the edition experiments

Run `python tooling/tuning.py` for the Chapter 14 protected-positive comparison and `python tooling/pair_profile.py` for the Chapter 16 pair-cardinality profile. Recorded edition observations are in `docs/evidence/tuning.json` and `docs/evidence/pair-profile.json`; reruns write to `build/`. Timing values vary by host. These scripts make no native performance or production prevalence claim.
