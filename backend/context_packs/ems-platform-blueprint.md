# EMS Platform Blueprint (core.ems.platform)

Purpose: planner
Scope: project
Project Key: core.ems.platform

## Goal (MVP)
- Web UI (CRUD devices, reports)
- Platform control capability to provision/manage EMS instances
- Manager demo env + operator single-tenant env

## Constraints/Defaults
- TLS: nginx + ACME
- AuthN: OIDC (default Google for MVP), config-driven
- Auth tokens: JWT between React UI and API
- AuthZ: RBAC (Admin/Operator/Viewer), plus platform-level roles (Provider/Manager/Operator)
- DNS: Route 53 integration for instance subdomains
- Runtime: docker-compose on provisioned EC2
- Logging: runs/logs/artifacts via Xyn

## Tenancy
- Provider owns control plane
- Manager demo env
- Operator env per operator

## Environments
- manager-demo: ems-demo.<base_domain>
- operator-example: ems-operator-example.<base_domain>

## Modules Required (Scaffold)
- app-web-stack, authn-oidc, authz-rbac, ingress-nginx-acme, dns-route53
- mikrotik-mgmt, poncan-mgmt, voltha-integration, oktopus-integration (scaffold only)

## Acceptance Checks
- HTTPS login works (ACME)
- OIDC login works
- JWT minted/accepted by API
- RBAC works (admin CRUD, viewer reports-only)
- Deploy flow works (generate plan/spec, deploy to selected instance, artifacts show success)
