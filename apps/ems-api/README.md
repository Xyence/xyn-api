# EMS API

FastAPI scaffold for the EMS platform.

## Run
- `pip install -r requirements.txt`
- `uvicorn ems_api.main:app --reload`

## Dev JWT
Set `EMS_JWT_SECRET` and issue a dev token:

```bash
export EMS_JWT_SECRET=dev-secret-change-me
python scripts/issue_dev_token.py
```

Use the token to call `/api/me` through nginx:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/me
```

## Migrations
Apply migrations before running the API:

```bash
alembic -c alembic.ini upgrade head
```
