#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)

if [ "${VERIFY_DOCKER:-}" != "1" ]; then
  echo "VERIFY_DOCKER not set; skipping Docker verification."
  exit 0
fi

cleanup() {
  docker compose -f "$ROOT_DIR/docker-compose.yml" down -v
}

trap cleanup EXIT

docker compose -f "$ROOT_DIR/docker-compose.yml" up -d --build
healthy=0
for i in {1..30}; do
  if curl -fsS http://localhost:8080/health >/dev/null; then
    healthy=1
    break
  fi
  sleep 1
done

if [ "$healthy" -ne 1 ]; then
  echo "Health check failed: /health did not become ready in time."
  exit 1
fi

curl -fsS http://localhost:8080/api/health >/dev/null
curl -fsS -o /dev/null -w "%{http_code}\n" http://localhost:8080/ | grep -E "^(200|302)$"
