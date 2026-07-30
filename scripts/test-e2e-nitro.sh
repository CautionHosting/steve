#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ACTION=${1:-all}
ZERO_PCR=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

require_value() {
  name=$1
  value=$2
  if [ -z "$value" ]; then
    echo "$name is required" >&2
    exit 2
  fi
}

validate_pcr() {
  name=$1
  value=$2
  if [ "${#value}" -ne 96 ]; then
    echo "$name must contain exactly 96 hexadecimal characters" >&2
    exit 2
  fi
  case "$value" in
    *[!0-9a-fA-F]*)
      echo "$name must contain only hexadecimal characters" >&2
      exit 2
      ;;
  esac
  if [ "$value" = "$ZERO_PCR" ]; then
    echo "$name must be nonzero; deploy without Caution debug mode" >&2
    exit 2
  fi
}

require_value STEVE_REMOTE_ORIGIN "${STEVE_REMOTE_ORIGIN:-}"
require_value STEVE_KEY_EXCHANGE "${STEVE_KEY_EXCHANGE:-}"
require_value STEVE_EXPECTED_PCR0 "${STEVE_EXPECTED_PCR0:-}"
require_value STEVE_EXPECTED_PCR1 "${STEVE_EXPECTED_PCR1:-}"
require_value STEVE_EXPECTED_PCR2 "${STEVE_EXPECTED_PCR2:-}"

case "$STEVE_KEY_EXCHANGE" in
  X25519|XWING-DRAFT10) ;;
  *)
    echo "STEVE_KEY_EXCHANGE must be exactly X25519 or XWING-DRAFT10" >&2
    exit 2
    ;;
esac

case "$ACTION" in
  all|browser|rust) ;;
  *)
    echo "usage: $0 [all|browser|rust]" >&2
    exit 2
    ;;
esac

validate_pcr STEVE_EXPECTED_PCR0 "$STEVE_EXPECTED_PCR0"
validate_pcr STEVE_EXPECTED_PCR1 "$STEVE_EXPECTED_PCR1"
validate_pcr STEVE_EXPECTED_PCR2 "$STEVE_EXPECTED_PCR2"

run_browser() {
  make -C "$ROOT_DIR/steve-js-sdk" build-test-assets
  if [ -n "${STEVE_E2E_BROWSER:-}" ]; then
    STEVE_E2E_PROFILE=nitro \
      npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e
  elif [ -d "/Applications/Google Chrome.app" ]; then
    STEVE_E2E_PROFILE=nitro \
    STEVE_E2E_BROWSER_CHANNEL=chrome \
      npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e
  else
    STEVE_E2E_PROFILE=nitro \
      npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e
  fi
}

case "$ACTION" in
  all)
    run_browser
    "$ROOT_DIR/scripts/test-sdk-nitro.sh"
    ;;
  browser)
    run_browser
    ;;
  rust)
    "$ROOT_DIR/scripts/test-sdk-nitro.sh"
    ;;
esac
