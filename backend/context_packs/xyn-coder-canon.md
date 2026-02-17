# Xyn Coder Canon (Global)

Purpose: coder
Scope: global

## CodegenResult v1
- Schema file: `schemas/codegen_result.v1.schema.json`
- Output must conform to `schema_version: codegen_result.v1`.
- Always emit `patches` (unified diff) for changes. `write_files` may appear for new files, but patches are preferred.

## Repo Targets (Defaults)
- `xyn-api`:
  - url: `https://github.com/Xyence/xyn-api`
  - path_root: `services/<blueprint_slug>/api`
- `xyn-ui`:
  - url: `https://github.com/Xyence/xyn-ui`
  - path_root: `services/<blueprint_slug>/web`

## Coding Standards
- Python: Black-friendly formatting, type hints where practical, keep modules small.
- React/TS: functional components, hooks, no class components.
- Infra: docker-compose at repo root or under `apps/*/deploy` with clear README.

## Output Contract
- Always include `commands_executed` entries for verification.
- No secrets. Use placeholders or `secretRef` notation.
- Always include `files_changed` and a concise `summary`.

## Safety
- Never embed real credentials.
- Prefer idempotent scaffolds and explicit TODO markers.
