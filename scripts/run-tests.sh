#!/usr/bin/env bash
# Dựng Redis + app sạch, chạy toàn bộ test, ghi evidence/ và quét bí mật trong evidence.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || python3 scripts/gen_env.py
export LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)"

docker compose --profile test down -v --remove-orphans
docker compose --profile test build
docker compose up -d --wait redis app

rm -rf evidence
mkdir -p evidence
status=0
docker compose --profile test run --rm tests 2>&1 | tee evidence/pytest-output.txt || status=$?

docker compose logs --no-color app > evidence/app-stdout.log
python3 scripts/check_no_secrets.py evidence | tee evidence/secret-scan.txt || status=1
exit "$status"
