# EMS Local Chassis

This stack runs the EMS API + UI locally using Docker Compose.

## Repo Layout
This compose file assumes you have these repos side-by-side:

- `../xyn-api`
- `../xyn-ui`

## Usage
From the `xyn-api` repo root:

```bash
docker compose -f apps/ems-stack/docker-compose.yml up -d --build
```

If your UI repo lives elsewhere, set:

```bash
export XYN_UI_PATH=/absolute/path/to/xyn-ui/apps/ems-ui
```

To run with verification checks (Docker required):

```bash
VERIFY_DOCKER=1 docker compose -f apps/ems-stack/docker-compose.yml up -d --build
```

Open:
- http://localhost:8080/
- http://localhost:8080/health
- http://localhost:8080/api/health

To stop:

```bash
docker compose -f apps/ems-stack/docker-compose.yml down -v
```
