# Onboarding + Route-bound Docs Design Note

## Route-bound docs
- Docs are implemented as `doc_page` entries in the existing Artifact Registry (`ArtifactType=doc_page`), not a parallel model.
- Route binding lives in `Artifact.scope_json.route_bindings` and markdown content lives in `ArtifactRevision.content_json.body_markdown`.
- `GET /xyn/api/docs/by-route?route_id=...` resolves the highest-priority matching doc for the active route.
- Draft/publish transitions are logged via `ArtifactEvent` (`doc_created`, `doc_updated`, `doc_published`).

## Onboarding tour
- Tour definitions are delivered via backend endpoint (`/xyn/api/tours/<slug>`).
- UI overlay executes steps by route + selector and persists per-user progress in local storage.
- Missing selectors do not hard-fail the flow; the step continues with a fallback notice.

## AI foundation
- Added `ModelProvider`, `ModelConfig`, and `AgentPurpose` for configurable purpose-specific models.
- `/xyn/api/ai/purposes` exposes current purpose config.
- `/xyn/api/ai/purposes/:slug` supports admin updates.
- This intentionally stops short of RAG/indexing; doc artifacts are now structured and available for future Context Pack ingestion.
