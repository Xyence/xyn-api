# xyn-api

Django API + admin backend for Xyn. Public content is served by xyn-ui and loaded from `/xyn/api/public/*`.

## Stack
- Django + Django REST Framework
- PostgreSQL
- Docker Compose

## Quick start
1. Copy env file
   - `cp backend/.env.example backend/.env`
2. Update Google OAuth values in `backend/.env` if using SSO.
3. Launch services:
   - `docker compose up --build`
4. Apply migrations and create an admin user:
   - `docker compose exec backend python manage.py migrate`
   - `docker compose exec backend python manage.py createsuperuser`
5. Admin panel: `http://localhost:8000/admin/`
6. Public site is served by xyn-ui (via nginx in prod).

## Production reverse proxy (Nginx + Certbot)
Use the production compose file to enable HTTPS. This is **not** required for local dev.

1) Set your domain in an env file (example `prod.env`):
```
DOMAIN=xyence.io
```

2) Start core services + nginx (xyn-ui served as the public site):
```
docker compose --env-file prod.env -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

3) Obtain the first certificate (root + www):
```
DOMAIN=xyence.io docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm \
  -p 80:80 -p 443:443 --entrypoint certbot certbot certonly --standalone \
  -d xyence.io -d www.xyence.io --email you@xyence.io --agree-tos --no-eff-email
```

4) Reload nginx:
```
docker compose --env-file prod.env -f docker-compose.yml -f docker-compose.prod.yml exec nginx nginx -s reload
```

The `nginx-reload` service automatically reloads nginx every 12 hours to pick up renewed certificates.

## Static files in production
Collect Django static files (admin CSS/JS) after first deploy or when dependencies change:
```
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec backend python manage.py collectstatic --noinput
```

## Google SSO
- Provide `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `backend/.env`.
- The admin login page includes a Google sign-in button at `http://localhost:8000/admin/`.
- For new installs, create your first superuser via `createsuperuser`, then add staff privileges to Google users if needed.
- In Google Cloud OAuth settings, add `http://localhost:8000/accounts/google/login/callback/` (or your production host) as an authorized redirect URI.

## Content management
- Pages/MenuItems/WebSections/Articles are managed in Django admin.
- Public API is available at:
  - `/xyn/api/public/menu`
  - `/xyn/api/public/pages`
  - `/xyn/api/public/pages/:slug`
  - `/xyn/api/public/pages/:slug/sections`
  - `/xyn/api/public/home`
  - `/xyn/api/public/articles`
  - `/xyn/api/public/articles/:slug`

## Public site (xyn-ui)
- xyn-ui is the public frontend for `https://xyence.io` and consumes the public API endpoints above.
- All traffic is served on the primary domain; `xyn.xyence.io` is no longer used.

## AI Studio
- Create an `OpenAI Config` in admin to store your API key and default model.
- Access AI Studio at `http://localhost:8000/admin/ai-studio/` to generate drafts.
- Each AI draft is stored as an `ArticleVersion` and applied to the article as a draft.

## Blueprint Pipeline (Local)
1. Seed context packs:
```
docker compose exec backend python manage.py seed_context_packs
```
2. Create or update a blueprint in xyn-ui, then click `Submit & Queue DevTasks`.
3. Ensure the worker is running:
```
docker compose up -d worker
```
4. The pipeline will generate `implementation_plan.json`, queue work-item dev tasks, and emit `codegen_result.json` artifacts with patches.

Optional codegen flags:
- `XYENCE_CODEGEN_GIT_TOKEN` for cloning private repos
- `XYENCE_CODEGEN_COMMIT=1` to commit patches
- `XYENCE_CODEGEN_PUSH=1` to push the codegen branch

## Xyn Seed (service management)
- Manage long-running releases at `http://localhost:8000/admin/xyn-seed/`.
- Configure the control plane with env vars:
  - `XYNSEED_BASE_URL` (default: `http://localhost:8001/api/v1`)
  - `XYNSEED_API_TOKEN` (optional bearer token)
  - Environment: `XYNSEED_BASE_URL`, `XYNSEED_API_TOKEN`
 - When running via Docker Compose on Linux, the default `XYNSEED_BASE_URL` uses `host.docker.internal` and `extra_hosts` to reach the host.

## Runtime Substrate Detection
Xyn automatically registers the host running `xyn-api` as a local instance in the Instances UI.

Configuration:
- `XYENCE_RUNTIME_SUBSTRATE` (default: `auto`)
  - `auto` attempts detection in order: EC2 IMDSv2, ECS/Fargate metadata, Kubernetes, Docker, then local.
  - You can force a mode with: `ec2`, `fargate`, `k8s`, `docker`, `local`.

Overrides (optional):
- `XYENCE_LOCAL_INSTANCE_ID`
- `XYENCE_LOCAL_INSTANCE_NAME`
- `XYENCE_LOCAL_AWS_REGION`
- `XYENCE_LOCAL_INSTANCE_TYPE`
- `XYENCE_LOCAL_AMI_ID`
- `XYENCE_LOCAL_STATUS`
- `XYENCE_LOCAL_ENVIRONMENT_ID`

## EMS TLS / Ingress Contract
- `tls.mode=host-ingress`: host-level Traefik owns ports `80/443`; app compose must not publish those host ports.
- `tls.mode=embedded`: app stack owns TLS termination (legacy).
- `ingress.routes[]` describes host to service to port mapping and compiles to Traefik labels.
- Host ingress runtime files:
  - `/opt/xyn/ingress/compose.ingress.yml`
  - `/opt/xyn/ingress/acme/acme.json`
- Required infra for ACME HTTP-01:
  - DNS A record points FQDN to the target host IP
  - inbound `80/443` reachable on the target host

## Shared OIDC Login and Branding
- Shared login entrypoint for all apps:
  - `/auth/login?appId=<appId>&returnTo=<url>`
- OIDC provider/app-client config is DB-managed:
  - `Platform -> Identity Providers`
  - `Platform -> OIDC App Clients`
- Branding is DB-managed:
  - `Platform -> Branding`
- Return URL safety:
  - Relative paths are allowed.
  - Absolute URLs must match `XYENCE_ALLOWED_RETURN_HOSTS` or app-configured redirect hosts.
- ENV fallback behavior:
  - If no OIDC app client is configured, backend falls back to env-based OIDC and logs:
    - `Using ENV OIDC fallback (no app client configured)`

## Xyn Manages Xyn (MVP)
- Deployments now track post-deploy verification and rollback metadata.
- `EnvironmentAppState` tracks per-environment app release state:
  - `current_release`
  - `last_good_release`
  - `last_deployed_at`
  - `last_good_at`
- Failed deployments can trigger rollback to `last_good_release` using the same deployment path.
- Internal rollback endpoint:
  - `POST /xyn/internal/deployments/<deployment_id>/rollback`

## Platform Architect Role
- New role: `platform_architect`
- This role can:
  - Publish control-plane releases (`xyn-api`, `xyn-ui`)
  - Deploy/rollback control-plane releases
  - Manage platform OIDC and branding settings
- `platform_admin` retains full access.

## Guided Exercise
- UI now includes `Platform -> Guides` with:
  - `Xyn Quickstart Exercise (Developer Walkthrough)`
  - a copyable starter blueprint prompt for demo prep

## Bug / Feature Report Facility
- Global hotkey in xyn-ui: `Ctrl+Shift+B` (or `Cmd+Shift+B` on macOS) opens the report overlay.
- API endpoints:
  - `POST /api/v1/reports` (multipart: `payload` JSON + `attachments[]`)
  - `GET /api/v1/reports/<report_id>`
  - `GET/PUT /api/v1/platform-config` (platform admin)
- Reports store structured context, attachments, and metadata for future automation.

### Platform Config (Storage + Notifications)
- Configure in UI: `Platform -> Platform Settings`.
- Storage:
  - `local` provider for dev fallback (`/tmp/xyn-uploads` by default)
  - `s3` provider for production object storage
- Notifications:
  - Discord webhook (via SecretRef only)
  - AWS SNS topic

### SecretRefs
- Discord webhook URL must be provided as a SecretRef reference:
  - `secret_ref:<uuid>` or a platform SecretRef name
- Secret values are never stored in report records and are resolved at send time.

### S3 Storage Behavior
- Attachments are written to:
  - `{prefix}/reports/{report_id}/{attachment_id}-{sanitized_filename}`
- Objects are private.
- Notification payloads use short-lived pre-signed GET links for S3 attachments.

### Local Dev Fallback
- If no S3 provider is configured, local storage is used.
- Default local attachment path:
  - `/tmp/xyn-uploads`

## Branding Tokens and Theme CSS
- New endpoints for generated app theming:
  - `GET /xyn/api/branding/tokens?app=<app_key>`
  - `GET /xyn/api/branding/theme.css?app=<app_key>`
- `tokens` returns merged global + per-app branding values in a normalized token shape.
- `theme.css` returns CSS variables (`--xyn-*`) with:
  - `ETag`
  - `Cache-Control: public, max-age=300`
  - `Access-Control-Allow-Origin: *`
- Generated web apps can load this stylesheet directly from the control-plane domain and keep local fallbacks for resilience.

## Preview As Role (Authorization Simulation)
- Endpoints:
  - `POST /xyn/api/preview/enable` with `{ roles: string[], readOnly: boolean }`
  - `POST /xyn/api/preview/disable`
  - `GET /xyn/api/preview/status`
- Downward-only policy:
  - `platform_owner` -> may preview any platform role
  - `platform_admin` -> may preview `platform_architect`, `platform_operator`, `app_user`
  - `platform_architect` -> may preview `platform_operator`, `app_user`
  - `platform_operator` / `app_user` -> preview denied
- Preview state is server session scoped and expires automatically after 60 minutes.
- In preview mode, write requests are blocked server-side with:
  - `{ "code": "PREVIEW_READ_ONLY", "message": "Preview mode is read-only." }`
- Audit messages emitted:
  - `PreviewEnabled`, `PreviewDisabled`, `PreviewRejected`
