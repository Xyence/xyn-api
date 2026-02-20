# Governance Slice Note (Workspaces + Artifact Registry)

## Workspace-based navigation
Shine now uses a stable workspace-context navigation model:
- Home
- Artifacts
- Activity
- People & Roles
- Settings

A workspace switcher in the left navigation header controls the active workspace context used by all pages and API calls.

## Artifact lifecycle and termination authority
Artifact registry introduces explicit lifecycle states:
- `draft`
- `reviewed`
- `ratified`
- `published`
- `deprecated`

Publishing is guarded by workspace RBAC + termination authority:
- actor must have `publisher` (or `admin`) workspace role
- actor must have termination authority (`admin` role or membership flag)

Lifecycle and moderation actions are written to immutable `ArtifactEvent` rows (append-only behavior in API usage).

## Django compatibility and deprecation plan
Compatibility is preserved by migrating legacy `Article` records into `Artifact` + `ArtifactRevision` + `ArtifactExternalRef`.

Public article endpoints now resolve published article artifacts by slug mappings and return:
- markdown when available (`body_markdown`)
- html fallback (`body_html`)

Legacy `Article` read fallback remains in public views for transition safety.

Django admin article editing is disabled (`ArticleAdmin` add/change/delete disabled) to avoid dual-truth drift while Shine becomes the editorial source of truth.
