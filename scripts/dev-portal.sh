#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${TMPDIR:-/tmp}/getai-run-8417.yaml"
BACKEND_LOG="${TMPDIR:-/tmp}/getai-run-8417.log"
FRONTEND_LOG="${TMPDIR:-/tmp}/getai-run-4173.log"

cd "$ROOT"

cp config.example.yaml "$CONFIG_PATH"
perl -0pi -e 's/port: 8317/port: 8417/' "$CONFIG_PATH"

if lsof -ti tcp:8417 >/dev/null 2>&1; then
  lsof -ti tcp:8417 | xargs kill
fi

if ! lsof -ti tcp:4173 >/dev/null 2>&1; then
  nohup python3 -m http.server 4173 --directory website >"$FRONTEND_LOG" 2>&1 &
fi

export_env=""
if [ -n "${PGSTORE_DSN:-}" ]; then
  export_env="PGSTORE_DSN=$PGSTORE_DSN"
fi
if [ -n "${USAGE_PG_DSN:-}" ]; then
  export_env="${export_env} USAGE_PG_DSN=$USAGE_PG_DSN"
fi
if [ -n "${PGSTORE_SCHEMA:-}" ]; then
  export_env="${export_env} PGSTORE_SCHEMA=$PGSTORE_SCHEMA"
fi
if [ -n "${USAGE_PG_SCHEMA:-}" ]; then
  export_env="${export_env} USAGE_PG_SCHEMA=$USAGE_PG_SCHEMA"
fi

if [ -n "$export_env" ]; then
  echo "Using PostgreSQL environment variables: $export_env"
  eval "nohup env $export_env go run ./cmd/server --config \"$CONFIG_PATH\" --no-browser >\"$BACKEND_LOG\" 2>&1 &"
else
  nohup go run ./cmd/server --config "$CONFIG_PATH" --no-browser >"$BACKEND_LOG" 2>&1 &
fi

echo "Frontend: http://127.0.0.1:4173/"
echo "Backend:  http://127.0.0.1:8417/"
echo "Logs:"
echo "  $FRONTEND_LOG"
echo "  $BACKEND_LOG"
