# Xyence Web

Django + React application for Xyence consulting, including a publishing system for articles and admin management.

## Stack
- Django + Django REST Framework
- React (Vite)
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
6. Frontend: `http://localhost:8080/`

## Production reverse proxy (Nginx + Certbot)
Use the production compose file to enable HTTPS. This is **not** required for local dev.

1) Set your domain in an env file (example `prod.env`):
```
DOMAIN=xyence.io
```

2) Start core services + nginx:
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
- Articles are managed in Django admin with a rich-text editor.
- Public API is available at `/api/articles/` and `/api/articles/:slug/`.

## AI Studio
- Create an `OpenAI Config` in admin to store your API key and default model.
- Access AI Studio at `http://localhost:8000/admin/ai-studio/` to generate drafts.
- Each AI draft is stored as an `ArticleVersion` and applied to the article as a draft.

## Xyn Seed (service management)
- Manage long-running releases at `http://localhost:8000/admin/xyn-seed/`.
- Configure the control plane with env vars:
  - `XYN_SEED_BASE_URL` (default: `http://localhost:8001/api/v1`)
  - `XYN_SEED_API_TOKEN` (optional bearer token)
  - Legacy aliases: `SHINESEED_BASE_URL`, `SHINESEED_API_TOKEN`
 - When running via Docker Compose on Linux, the default `XYN_SEED_BASE_URL` uses `host.docker.internal` and `extra_hosts` to reach the host.

## GitHub Context (AI Studio)
- Create a `GitHub Config` with a personal access token and organization name.
- Use the `GitHub Config` admin action to sync repositories.
- Select repositories in AI Studio to pull relevant markdown context into prompts.
 - You can also connect GitHub via OAuth (allauth GitHub provider) and leave the PAT empty.
# xyence-web
