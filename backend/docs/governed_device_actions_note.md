## Governed Device Actions (MVP: `device.reboot`)

This slice implements device write operations as governed artifacts aligned with Xyn governance primitives, without introducing a parallel governance subsystem.

### Alignment to Governance Primitives

- Legibility:
  - `DraftAction` captures requested action type/class and sanitized parameters.
  - `DraftActionEvent` stores explicit lifecycle transitions.
- Provenance:
  - `DraftAction.provenance_json` stores request/correlation/source metadata.
- Typed material:
  - Stable action taxonomy (`device.reboot`, `device.factory_reset`, `device.push_config`, `credential_ref.attach`, `adapter.enable`, `adapter.configure`) and action classes.
- Separation (provisional vs binding):
  - Action lifecycle supports `pending_verification`, `pending_ratification`, and terminal execution states.
- Promotion rules:
  - Confirmation and ratification gates are policy-driven, then transition to execution.
- Termination authority:
  - Ratification role gate is explicit (`ems_admin` by default when required).
- Auditability:
  - Immutable `DraftActionEvent` transition log + immutable `ExecutionReceipt` per execution attempt.
- Corrigibility:
  - Historical events and receipts remain queryable after terminal status.

### Policy and RBAC

- Tenant-scoped policy is resolved from defaults plus optional tenant metadata overrides:
  - `tenant.metadata_json.ems_action_policies[action_type]`
  - `tenant.metadata_json.ems_action_policies_by_instance[instance_ref][action_type]`
- Default reboot policy:
  - `requires_confirmation=true`
  - `requires_ratification=false` (fast path)
  - request roles: `ems_operator`, `ems_admin`
  - execute roles: `ems_admin` or `system`
- Role mapping uses existing tenant membership:
  - `tenant_viewer -> ems_viewer`
  - `tenant_operator -> ems_operator`
  - `tenant_admin -> ems_admin`

### API Lifecycle

- `POST /xyn/api/devices/{device_id}/actions`
- `POST /xyn/api/actions/{action_id}/confirm`
- `POST /xyn/api/actions/{action_id}/ratify`
- `POST /xyn/api/actions/{action_id}/execute`
- `GET /xyn/api/actions?device_id=...`
- `GET /xyn/api/actions/{action_id}`
- `GET /xyn/api/actions/{action_id}/receipts`

### Protocol Gateway Compatibility

Execution is isolated behind `_execute_draft_action` and policy evaluation helpers in `xyn_api.py`. This keeps the API contract stable while allowing later replacement of inline execution with a protocol-gateway/worker transport.
