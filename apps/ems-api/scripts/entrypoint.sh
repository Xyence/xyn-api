#!/usr/bin/env sh
set -e

if [ -z "${DATABASE_URL:-}" ]; then
  echo "DATABASE_URL is required"
  exit 1
fi

echo "Waiting for database..."
python - <<'PY'
import os
import time

import psycopg

url = os.environ.get("DATABASE_URL", "").strip()
if url.startswith("postgresql+psycopg://"):
    url = "postgresql://" + url[len("postgresql+psycopg://"):]
elif url.startswith("postgres://"):
    url = "postgresql://" + url[len("postgres://"):]

for _ in range(30):
    try:
        conn = psycopg.connect(url, connect_timeout=2)
        conn.close()
        print("Database is ready")
        break
    except Exception:
        time.sleep(1)
else:
    raise SystemExit("Database did not become ready in time")
PY

echo "Running migrations..."
alembic -c /app/alembic.ini upgrade head

echo "Starting API..."
exec uvicorn ems_api.main:app --host 0.0.0.0 --port 8000
