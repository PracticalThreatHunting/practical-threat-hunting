# Book Figure Gallery

Supporting diagrams from the **Practical Threat Hunting** series. The manuscript source is not stored in this repository.

## Book 1 — Modern Techniques for the AI-Augmented SOC

### AI Validation Loop

![AI validation loop showing approved evidence entering AI assistance, followed by schema and evidence verification, analyst review, and documented output.](fig_3_1_ai_validation_loop.png)

Book 1 figure files:

- [`fig_1_1_hunt_lifecycle.png`](fig_1_1_hunt_lifecycle.png) — threat-hunt lifecycle.
- [`fig_1_2_disciplines.png`](fig_1_2_disciplines.png) — related defensive disciplines.
- [`fig_2_1_telemetry_map.png`](fig_2_1_telemetry_map.png) — telemetry relationship map.
- [`fig_3_1_ai_validation_loop.png`](fig_3_1_ai_validation_loop.png) — AI validation loop.
- [`fig_5_1_framework_stack.png`](fig_5_1_framework_stack.png) — framework stack.
- [`fig_part5_cross_domain.png`](fig_part5_cross_domain.png) — cross-domain hunting relationships.
- [`fig_20_1_campaign_workflow.png`](fig_20_1_campaign_workflow.png) — campaign-hunting workflow.
- [`fig_21_1_shadow_ai_visibility.png`](fig_21_1_shadow_ai_visibility.png) — shadow-AI visibility model.
- [`fig_23_1_machine_identity_baseline.png`](fig_23_1_machine_identity_baseline.png) — machine-identity baseline.
- [`fig_24_1_agent_action_boundary.png`](fig_24_1_agent_action_boundary.png) — AI-agent action boundary.
- [`fig_31_1_hunt_to_detection.png`](fig_31_1_hunt_to_detection.png) — hunt-to-detection transition.
- [`fig_32_1_hunt_library_record.png`](fig_32_1_hunt_library_record.png) — minimum hunt-library record.
- [`fig_34_1_ai_augmented_lifecycle.png`](fig_34_1_ai_augmented_lifecycle.png) — AI-augmented hunt lifecycle.

## Book 2 — Endpoint and Identity Threats

### Endpoint–Identity Pivot Loop

![Six-step endpoint-identity pivot loop: preserve the strongest event, resolve entities, pivot through identity and endpoint evidence, compare context, and record a conclusion.](book-02/endpoint_identity_pivot_loop.png)

### Evidence-Preserving AI Workflow

![Evidence-preserving AI workflow with approved evidence, AI-assisted work, schema, evidence, logic, and action gates, plus a return path when a gate fails.](book-02/ai_verification_gates.png)

### Session-Replay Evidence Chain

![Session-replay evidence chain connecting an endpoint candidate to entity resolution, authentication sequence, session discontinuity, resource activity, and analyst decision tests.](book-02/session_replay_evidence_chain.png)

### Hunt-to-Detection Promotion Ladder

![Six-stage promotion ladder from a security question through exploratory hunt, validated analytic, scheduled detection, correlated incident, and control improvement.](book-02/hunt_detection_promotion_ladder.png)

### Cross-Domain Entity Map

![Cross-domain entity map connecting user, device, process, file, session, IP and time, application, and resource records through source-specific identifiers.](book-02/cross_domain_entity_map.png)

Book 2 figures are author-created analytical models. They support the investigation workflows described in the book and are not product architecture diagrams.

## Book 3 — Cloud and SaaS Environments

### Cloud and SaaS Evidence-Plane Map

![Six evidence planes—identity, control, data, application, workload, and network—connected through shared identity, session, resource, time, and coverage context.](book-03/cloud_saas_evidence_plane_map.png)

### Human, Application, and Workload Identity Graph

![Human, application, and workload identities connect through authorization or trust, credential or session issuance, and actions against target resources.](book-03/human_application_workload_identity_graph.png)

### Temporary Credential Provenance Chain

![A five-stage chain from originating identity through issuer or trust, temporary session, provider action, and target effect, with stable correlation keys at each stage.](book-03/temporary_credential_provenance_chain.png)

### Cloud Administration Command Evidence Chain

![A five-stage evidence chain from caller session through a cloud administration request and service state to guest evidence and an observed effect, emphasizing that API success alone does not prove execution.](book-03/cloud_admin_command_evidence_chain.png)

### SaaS API Activity Investigation Chain

![A five-stage SaaS investigation chain connecting authorization, client and token context, an API request, resource result, and downstream audit evidence.](book-03/saas_api_activity_investigation_chain.png)

### Cross-Cloud Capstone Evidence Graph

![An origin and trust node connects to AWS, Azure, Microsoft 365, and Google Workspace evidence, which converge in an evidence ledger containing identifiers, coverage, clock bounds, contradictions, and confidence.](book-03/cross_cloud_capstone_evidence_graph.png)

Book 3 figures are author-created analytical models. They describe evidence relationships and investigation workflows, not provider architecture or guaranteed telemetry coverage.
