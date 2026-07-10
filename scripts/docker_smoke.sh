#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f .env ]]; then cp .env.example .env; fi
# .env.example contains shell-compatible KEY=VALUE pairs. Export them so the
# smoke-test client uses the same credentials and ports as Docker Compose.
set -a
# shellcheck disable=SC1091
source .env
set +a
mkdir -p lab-output uploads

docker compose up -d --build postgres migrate api worker gateway
for _ in $(seq 1 60); do
  if curl -fsS http://localhost:${GATEWAY_PORT:-8080}/health >/dev/null; then break; fi
  sleep 2
done
curl -fsS http://localhost:${GATEWAY_PORT:-8080}/health | tee lab-output/api-health.json

TOKEN=$(curl -fsS -X POST "http://localhost:${GATEWAY_PORT:-8080}/auth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=${APP_ADMIN_EMAIL:-admin@example.com}" \
  --data-urlencode "password=${APP_ADMIN_PASSWORD:-ChangeMe-Now-123!}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -fsS "http://localhost:${GATEWAY_PORT:-8080}/users/me" \
  -H "Authorization: Bearer $TOKEN" | tee lab-output/api-user.json

printf 'safe demonstration file\n' > lab-output/demo-upload.txt
UPLOAD=$(curl -fsS -X POST "http://localhost:${GATEWAY_PORT:-8080}/uploads" \
  -H "Authorization: Bearer $TOKEN" \
  -F 'file=@lab-output/demo-upload.txt;type=text/plain')
printf '%s\n' "$UPLOAD" | tee lab-output/api-upload.json
UPLOAD_ID=$(printf '%s' "$UPLOAD" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

for _ in $(seq 1 30); do
  STATUS=$(curl -fsS "http://localhost:${GATEWAY_PORT:-8080}/uploads/$UPLOAD_ID" \
    -H "Authorization: Bearer $TOKEN")
  printf '%s\n' "$STATUS" > lab-output/api-upload-status.json
  STATE=$(printf '%s' "$STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
  [[ "$STATE" == "clean" ]] && break
  sleep 1
done

echo 'Docker smoke test completed.'
