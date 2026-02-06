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
sleep 2
healthy=0
for i in {1..60}; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health || true)
  if [ "$code" = "200" ]; then
    healthy=1
    break
  fi
  sleep 1
done

if [ "$healthy" -ne 1 ]; then
  echo "Health check failed: /health did not become ready in time."
  docker compose -f "$ROOT_DIR/docker-compose.yml" logs --tail=200 ems-api || true
  docker compose -f "$ROOT_DIR/docker-compose.yml" logs --tail=200 nginx || true
  docker compose -f "$ROOT_DIR/docker-compose.yml" logs --tail=200 ems-ui || true
  exit 1
fi

api_healthy=0
for i in {1..30}; do
  api_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/health || true)
  if [ "$api_code" = "200" ]; then
    api_healthy=1
    break
  fi
  sleep 1
done

if [ "$api_healthy" -ne 1 ]; then
  echo "API health check failed: /api/health did not become ready in time."
  docker compose -f "$ROOT_DIR/docker-compose.yml" logs --tail=200 ems-api || true
  docker compose -f "$ROOT_DIR/docker-compose.yml" logs --tail=200 nginx || true
  exit 1
fi
sleep 2
for i in {1..10}; do
  status_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/me)
  if [ "$status_code" = "401" ]; then
    break
  fi
  sleep 1
done
if [ "$status_code" != "401" ]; then
  echo "Expected /api/me to return 401 without token, got ${status_code}"
  exit 1
fi
viewer_token=$(docker compose -f "$ROOT_DIR/docker-compose.yml" exec -T ems-api python scripts/issue_dev_token.py --role viewer)
for i in {1..10}; do
  viewer_list_code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${viewer_token}" http://localhost:8080/api/devices)
  if [ "$viewer_list_code" = "200" ]; then
    break
  fi
  sleep 1
done
if [ "$viewer_list_code" != "200" ]; then
  echo "Expected viewer GET /api/devices to return 200, got ${viewer_list_code}"
  exit 1
fi
viewer_status=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${viewer_token}" -H "Content-Type: application/json" -d '{"name":"dev-viewer"}' http://localhost:8080/api/devices)
if [ "$viewer_status" != "403" ]; then
  echo "Expected viewer POST /api/devices to return 403, got ${viewer_status}"
  exit 1
fi
admin_token=$(docker compose -f "$ROOT_DIR/docker-compose.yml" exec -T ems-api python scripts/issue_dev_token.py --role admin)
for i in {1..10}; do
  admin_me_code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${admin_token}" http://localhost:8080/api/me)
  if [ "$admin_me_code" = "200" ]; then
    break
  fi
  sleep 1
done
if [ "$admin_me_code" != "200" ]; then
  echo "Expected admin GET /api/me to return 200, got ${admin_me_code}"
  exit 1
fi
admin_post=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${admin_token}" -H "Content-Type: application/json" -d '{"name":"dev1"}' http://localhost:8080/api/devices)
if [ "$admin_post" != "200" ] && [ "$admin_post" != "201" ]; then
  echo "Expected admin POST /api/devices to return 200/201, got ${admin_post}"
  exit 1
fi
admin_list=$(curl -s -H "Authorization: Bearer ${admin_token}" http://localhost:8080/api/devices || true)
echo "$admin_list" | grep -q "dev1"

curl -fsS -H "Authorization: Bearer ${admin_token}" -H "Content-Type: application/json" -d '{"name":"persist1"}' http://localhost:8080/api/devices >/dev/null
docker compose -f "$ROOT_DIR/docker-compose.yml" restart ems-api
for i in {1..30}; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health || true)
  if [ "$code" = "200" ]; then
    break
  fi
  sleep 1
done
curl -fsS -H "Authorization: Bearer ${admin_token}" http://localhost:8080/api/devices | grep -q "persist1"

ui_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/)
if [ "$ui_code" != "200" ] && [ "$ui_code" != "302" ]; then
  echo "Expected UI root to return 200/302, got ${ui_code}"
  exit 1
fi

sleep 2
