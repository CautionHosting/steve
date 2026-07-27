#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE_FILE="$ROOT_DIR/tests/e2e/compose.yaml"
PROJECT_NAME=steve-e2e
ACTION=${1:-test}
STEVE_KEY_EXCHANGE=${STEVE_KEY_EXCHANGE:-X25519}

case "$STEVE_KEY_EXCHANGE" in
  X25519|XWING-DRAFT10) ;;
  *)
    echo "STEVE_KEY_EXCHANGE must be exactly X25519 or XWING-DRAFT10" >&2
    exit 2
    ;;
esac
export STEVE_KEY_EXCHANGE

compose() {
  docker compose --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE" "$@"
}

build_assets() {
  npm --prefix "$ROOT_DIR/steve-js-sdk" run build:e2e
}

wait_for_services() {
  attempts=0
  until curl --fail --silent http://127.0.0.1:3000/ >/dev/null \
    && curl --fail --silent http://127.0.0.1:49500/health >/dev/null; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 90 ]; then
      compose logs
      echo "STEVE E2E services did not become ready" >&2
      return 1
    fi
    sleep 1
  done
}

start() {
  build_assets
  compose up --build --detach
  wait_for_services
}

stop() {
  compose down --volumes --remove-orphans
}

cleanup_test() {
  status=$?
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ]; then
    echo "STEVE E2E failed; container logs follow:" >&2
    compose logs --no-color --tail 200 >&2 || true
  fi
  stop || true
  exit "$status"
}

run_playwright() {
  if [ -n "${STEVE_E2E_BROWSER:-}" ]; then
    npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e
  elif [ -d "/Applications/Google Chrome.app" ]; then
    STEVE_E2E_BROWSER_CHANNEL=chrome \
      npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e
  else
    npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e
  fi
}

case "$ACTION" in
  test)
    trap cleanup_test EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    start
    run_playwright
    ;;
  up)
    start
    echo "STEVE local E2E demo: http://127.0.0.1:3000"
    ;;
  down)
    stop
    ;;
  logs)
    compose logs --follow --tail 100
    ;;
  *)
    echo "usage: $0 [test|up|down|logs]" >&2
    exit 2
    ;;
esac
