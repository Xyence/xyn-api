# Articles As Governed Artifacts

## Workspace-Based Navigation
- Articles are first-class `Artifact(type=article)` records scoped to a workspace.
- Guides/help content is no longer a separate content model in new writes; guide content is represented by article categories (`guide`, `core-concepts`, `tutorial`) and route bindings in `scope_json.route_bindings`.
- Existing docs APIs (`/xyn/api/docs/*`) remain as compatibility shims and now resolve guide-category articles first.

## Lifecycle + Termination Authority
- Article lifecycle states use artifact lifecycle semantics: `draft -> reviewed -> ratified -> published -> deprecated`.
- Revisions are append-only (`ArtifactRevision`) and publishing/deprecation transitions emit explicit audit events (`ArtifactEvent`).
- Status transitions are explicit via `/xyn/api/articles/:id/transition`; publish/ratify is restricted to platform governance roles (`platform_admin`, `platform_architect`).

## Visibility + Categories
- Category and visibility are stored as article metadata in `scope_json`:
  - `category`: `web | guide | core-concepts | release-note | internal | tutorial`
  - `visibility_type`: `public | authenticated | role_based | private`
  - `allowed_roles` for role-based access
  - `route_bindings` for help overlay lookup
- Public article rendering continues through `/xyn/api/public/articles*` and reads published article artifacts with markdown/html fallback.

## Django Compatibility + Deprecation
- `migrate_governed_articles` command migrates:
  - legacy Django `Article` rows into governed `article` artifacts
  - legacy `doc_page` artifacts into governed guide-category `article` artifacts
- Migration preserves provenance using `provenance_json` and `ArtifactExternalRef`.
- Legacy Django article admin editing is already read-only to avoid dual-truth drift.
