# Xyn Planner Canon (Global)

Purpose: planner
Scope: global

## ImplementationPlan v1
- Schema file: `schemas/implementation_plan.v1.schema.json`
- Output must conform to `schema_version: implementation_plan.v1`.
- Primary output is `work_items[]` with actionable steps.

## Planning Algorithm
1. Parse blueprint spec and metadata into a module inventory and system goals.
2. Expand into ordered `work_items` with explicit repo targets, inputs, outputs, and verification.
3. Assign labels: `scaffold`, `auth`, `rbac`, `deploy`, `dns`, `reports`, `ui`, `api`, `infra`.
4. Ensure dependencies reflect build order: scaffold -> auth -> rbac -> features -> deploy.

## ReleaseSpec Expectations
ReleaseSpec must include:
- `base_domain` (string)
- `environments[]`: `name`, `subdomain`, `tls`, `auth`, `dns` settings
- `auth`: OIDC provider and client configuration placeholders
- `rbac`: role list and policy summary
- `compose`: docker-compose stack definitions

## ReleasePlan Rules
- Produce steps oriented around SSM + docker-compose.
- Steps must be deterministic and actionable.
- Do not include placeholder commands like `uname -a` unless `smoke_test=true` is explicitly set.

## Guardrails
- Planner produces plans/specs only. Do not write repo files.
- Always include `verify` commands for each work_item.
