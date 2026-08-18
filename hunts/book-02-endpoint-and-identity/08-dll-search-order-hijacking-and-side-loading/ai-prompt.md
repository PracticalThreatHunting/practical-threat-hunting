# AI-Assisted Analysis Prompt — Hunt 08

Use only data approved for the selected AI system. Treat the output as proposed analysis and verify every material claim against the underlying evidence.

```text
Analyze these executable-module pairs using only the supplied signer, path, hash, version, creation time, and prevalence fields.
Rank relationships that are rare, newly created, signer-mismatched, or loaded from user-writable locations.
For every candidate, state what package or software-inventory evidence is needed before escalation.
Do not infer a known vulnerability or malicious family from the filename alone.
```
