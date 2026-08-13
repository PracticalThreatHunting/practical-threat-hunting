# AI Validation Loop

Use AI to accelerate reasoning you can inspect—not to replace reasoning you cannot verify.

1. **Prompt** — state one clear analytical objective, relevant schema, time range, and assumptions.
2. **Inspect** — read the generated logic; identify tables, fields, joins, thresholds, exclusions, and derived values.
3. **Validate** — confirm schema and semantics against authoritative documentation or your platform schema browser.
4. **Execute** — run narrowly first; inspect raw events and row counts before scaling the time range.
5. **Interpret** — separate observed facts from model-generated explanation.
6. **Challenge** — ask what benign explanation fits, what evidence is missing, and how the query could be wrong.
7. **Pivot** — choose the next entity, time window, data source, or hypothesis based on validated evidence.

Never send sensitive telemetry to a model unless organizational policy and the model's data-handling controls allow it.
