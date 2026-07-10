#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

# .env.example contains shell-compatible KEY=VALUE pairs. Export them so the
# smoke-test client uses the same credentials and ports as Docker Compose.
set -a
# shellcheck disable=SC1091
source .env
set +a

mkdir -p lab-output uploads

print_diagnostics() {
  local exit_code=$?

  if [[ "$exit_code" -ne 0 ]]; then
    echo
    echo "Smoke test failed. Docker Compose status:"
    docker compose ps -a || true

    for service in gateway api migrate worker postgres; do
      echo
      echo "${service} logs:"
      docker compose logs --no-color --tail=200 "$service" || true
    done
  fi

  exit "$exit_code"
}

trap print_diagnostics EXIT

docker compose up -d --build \
  --wait \
  --wait-timeout 180 \
  postgres migrate api worker gateway

GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT:-8080}"

curl \
  --fail \
  --silent \
  --show-error \
  --retry 10 \
  --retry-delay 2 \
  --retry-connrefused \
  "${GATEWAY_URL}/health" |
  tee lab-output/api-health.json

TOKEN="$(${CURL_BIN:-curl} \
  --fail \
  --silent \
  --show-error \
  --retry 5 \
  --retry-delay 2 \
  --retry-connrefused \
  -X POST "${GATEWAY_URL}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=${APP_ADMIN_EMAIL:-admin@example.com}" \
  --data-urlencode "password=${APP_ADMIN_PASSWORD:-ChangeMe-Now-123!}" |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')"

curl \
  --fail \
  --silent \
  --show-error \
  "${GATEWAY_URL}/users/me" \
  -H "Authorization: Bearer ${TOKEN}" |
  tee lab-output/api-user.json

printf 'safe demonstration file\n' >lab-output/demo-upload.txt

UPLOAD="$(curl \
  --fail \
  --silent \
  --show-error \
  -X POST "${GATEWAY_URL}/uploads" \
  -H "Authorization: Bearer ${TOKEN}" \
  -F "file=@lab-output/demo-upload.txt;type=text/plain")"

printf '%s\n' "$UPLOAD" | tee lab-output/api-upload.json

UPLOAD_ID="$(printf '%s' "$UPLOAD" |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])')"

upload_completed=false

for _ in $(seq 1 30); do
  STATUS="$(curl \
    --fail \
    --silent \
    --show-error \
    "${GATEWAY_URL}/uploads/${UPLOAD_ID}" \
    -H "Authorization: Bearer ${TOKEN}")"

  printf '%s\n' "$STATUS" >lab-output/api-upload-status.json

  STATE="$(printf '%s' "$STATUS" |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["status"])')"

  if [[ "$STATE" == "clean" ]]; then
    upload_completed=true
    break
  fi

  if [[ "$STATE" == "rejected" || "$STATE" == "failed" ]]; then
    echo "Upload processing ended in unexpected state: ${STATE}" >&2
    exit 1
  fi

  sleep 1
done

if [[ "$upload_completed" != "true" ]]; then
  echo "Upload did not reach clean state within the timeout." >&2
  cat lab-output/api-upload-status.json >&2
  exit 1
fi

trap - EXIT
echo "Docker smoke test completed successfully."
