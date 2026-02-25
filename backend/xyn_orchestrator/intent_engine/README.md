# Xyn Intent Engine V1

Action vocabulary:
- `CreateDraft`
- `ProposePatch`
- `ApplyPatch` (apply endpoint only, never directly produced by LLM)
- `ShowOptions`
- `ValidateDraft`

Draft intake contract format:
- `required_fields`
- `optional_fields`
- `default_values`
- `option_sources`
- `inference_rules`

ResolutionResult schema:
- `status`
- `action_type`
- `artifact_type`
- `artifact_id`
- `summary`
- `missing_fields`
- `options`
- `proposed_patch`
- `draft_payload`
- `next_actions`
- `audit`

How to add artifact types:
1. Add a contract to `DraftIntakeContractRegistry`.
2. Extend deterministic validation/patch service for that artifact.
3. Add allowed type and fields in `types.py`.
4. Wire apply logic in API endpoint with deterministic validation.
