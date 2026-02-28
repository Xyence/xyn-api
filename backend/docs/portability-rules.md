# Portability Rules

## Required

- No secrets in package files.
- No environment-specific IDs as hard runtime dependencies.
- Environment values must be represented as bindings.
- Dependencies must be explicit and versioned.
- Re-installing the same package must be safe and idempotent.

## Binding model

Bindings are logical names (for example `BASE_URL`, `LLM_PROFILE_DEFAULT`, `VIDEO_PROVIDER`, `SMTP_PROFILE`).

Resolution order:

1. Install request overrides (`binding_overrides`)
2. Instance binding registry (`ArtifactBindingValue`)
3. Environment strategy (`resolution_strategy=environment`)
4. Non-secret `default_value`

Unresolved required bindings fail validation/install.

## Hooks and idempotency

Hooks must converge to the same state when replayed:

- `data_model`: `CREATE TABLE IF NOT EXISTS` style operations
- `app_shell`: deterministic registry upsert
- `auth_login`: deterministic registry upsert
- `ui_view`: deterministic registry upsert
- `workflow`: deterministic registry upsert

## Safety constraints

- Package import validates checksum integrity before install.
- All install attempts are auditable via immutable receipts.
- Upgrade operations preserve existing artifact identity where possible.
