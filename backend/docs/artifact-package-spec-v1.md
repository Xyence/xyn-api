# Artifact Package Spec v1

Artifact packages are deterministic ZIP bundles used to move installable artifacts across instances.

## Layout

- `manifest.json`
- `artifacts/<type>/<slug>/<version>/artifact.json`
- `artifacts/<type>/<slug>/<version>/payload/*`

## Manifest fields

- `format_version`: integer (`1` for v1)
- `package_name`: string
- `package_version`: semver
- `built_at`: ISO timestamp
- `platform_compatibility`: `{ min_version, max_version_optional, required_features[] }`
- `artifacts[]`: `{ type, slug, version, artifact_id, artifact_hash, dependencies[], bindings[] }`
- `checksums`: map of `path -> sha256`
- `entrypoints[]` (optional)

## Validation rules

- ZIP must contain `manifest.json`.
- All manifest artifacts must be unique by identity (`type + slug + version`).
- Semver is enforced for package and artifact versions.
- Every checksum entry must exist in ZIP and match sha256.
- Dependencies must resolve from:
  - included package artifacts, or
  - already installed local artifacts.

## Install flow

1. Validate structure + manifest schema.
2. Verify checksums.
3. Resolve dependencies.
4. Resolve bindings (instance settings -> overrides -> environment/defaults).
5. Topologically sort by dependency graph.
6. Install idempotently (`skip` when identity+hash already installed).
7. Run idempotent install hooks by artifact type.
8. Write immutable install receipt.

## Receipts

Every install attempt writes `ArtifactInstallReceipt` with:

- package identity/hash
- install mode (`install|upgrade|reinstall`)
- resolved bindings
- step operations log
- artifact changes summary
- final status (`success|failed|partial`)
