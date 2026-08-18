# AI-Assisted Analysis Prompt — Hunt 11

Use only data approved for the selected AI system. Treat the output as proposed analysis and verify every material claim against the underlying evidence.

```text
Build a directed graph from these verified authentication and endpoint events.
Nodes are accounts and devices; edges are successful remote authentications or confirmed remote execution.
Rank new or high-fan-out edges relative to the supplied administrative baseline.
For each edge, identify whether destination execution is observed, inferred, or absent.
Do not equate network access with code execution.
```
