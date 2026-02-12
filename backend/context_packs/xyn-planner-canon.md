# Xyn Planner Canon (Global)

Purpose: planner
Scope: global

## ImplementationPlan v1
- Schema file: `schemas/implementation_plan.v1.schema.json`
- Output must conform to `schema_version: implementation_plan.v1`.
- Primary output is `work_items[]` with actionable steps.
- Include `capabilities_required` and `module_refs` per work_item.
- Include `plan_rationale` with gaps detected and why the next slice was chosen.
- Use `module_catalog.v1.json` and `run_history_summary.v1.json` artifacts as inputs.

## Planning Algorithm
1. Read `module_catalog.v1.json` to determine available modules/capabilities.
2. Read `run_history_summary.v1.json` to avoid already-completed work items.
3. Parse blueprint spec and metadata into system goals and acceptance checks.
4. Identify gaps vs acceptance checks and select the next slice of work.
5. Expand into ordered `work_items` with explicit repo targets, inputs, outputs, and verification.
6. Assign labels: `scaffold`, `auth`, `rbac`, `deploy`, `dns`, `reports`, `ui`, `api`, `infra`, plus `module:<id>` and `capability:<cap>`.
7. Ensure dependencies reflect build order: scaffold -> auth -> rbac -> features -> deploy.

## ReleaseSpec Expectations
ReleaseSpec must include:
- `base_domain` (string)
- `environments[]`: `name`, `subdomain`, `tls`, `auth`, `dns` settings
- `auth`: OIDC provider and client configuration placeholders
- `rbac`: role list and policy summary
- `compose`: docker-compose stack definitions
- `tls.mode`: `host-ingress` or `embedded`
- `ingress.routes[]`: host -> service -> port mapping (voice-friendly intent)

## ReleasePlan Rules
- Produce steps oriented around SSM + docker-compose.
- Steps must be deterministic and actionable.
- Do not include placeholder commands like `uname -a` unless `smoke_test=true` is explicitly set.
- In `host-ingress` mode, apps do not bind host `80/443`; ingress stack owns those ports.

## Guardrails
- Planner produces plans/specs only. Do not write repo files.
- Always include `verify` commands for each work_item.
- Never select already completed work_items when run history marks them succeeded.
