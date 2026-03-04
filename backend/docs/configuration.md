# Runtime Configuration Migration (Seed-Owned)

`xyn-api` now expects runtime configuration from injected process environment (owned by `xyn-seed`/compose).

## Canonical Inputs

- `XYN_ENV`
- `XYN_BASE_DOMAIN`
- `XYN_AUTH_MODE` (`simple|oidc`)
- `XYN_INTERNAL_TOKEN`
- `XYN_OIDC_ISSUER` / `XYN_OIDC_CLIENT_ID` / `XYN_OIDC_ALLOWED_DOMAINS`
- `XYN_AI_PROVIDER` / `XYN_AI_MODEL`
- `XYN_OPENAI_API_KEY` / `XYN_GEMINI_API_KEY` / `XYN_ANTHROPIC_API_KEY` (seed-owned AI key inputs)

## Compatibility Behavior

- In local/dev only, `backend/.env` is still loaded if present, with a deprecation warning.
- Legacy aliases remain supported:
  - `DOMAIN` -> `XYN_BASE_DOMAIN`
  - `XYENCE_INTERNAL_TOKEN` -> `XYN_INTERNAL_TOKEN`
  - other `XYENCE_*` operational variables are backfilled from canonical `XYN_*` values.

## Production Requirement

Production compose disables `env_file` loading and relies on injected env only.

## Auth Modes

- `simple` (default): no OIDC bearer verification path.
- `oidc`: OIDC bearer verification and social auth restrictions are enabled.
