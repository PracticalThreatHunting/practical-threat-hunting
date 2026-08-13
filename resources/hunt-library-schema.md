# Minimum Hunt Record

A reusable hunt library should preserve:

- Hunt ID and title
- Hypothesis and threat rationale
- Owner and status
- ATT&CK / ATLAS / other mappings where useful
- Required telemetry and critical fields
- Query or notebook links by platform
- Baseline / normal-behavior notes
- Time window and population tested
- Findings and disposition
- Telemetry gaps and engineering actions
- Detection candidates or detections created
- Last validated date and next review date

Keep stable reasoning in the hunt record and volatile vendor-specific implementations in version-controlled query files.
