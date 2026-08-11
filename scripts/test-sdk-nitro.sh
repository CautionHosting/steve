#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

require_value() {
  name=$1
  value=$2
  if [ -z "$value" ]; then
    echo "$name is required" >&2
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

cargo test --locked --manifest-path "$ROOT_DIR/Cargo.toml" \
  -p steve-sdk --test nitro_e2e remote_nitro_e2e \
  -- --exact --ignored --nocapture
