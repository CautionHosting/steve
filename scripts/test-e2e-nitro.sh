#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -z "${STEVE_REMOTE_ORIGIN:-}" ]; then
  echo "STEVE_REMOTE_ORIGIN is required (for example, http://203.0.113.10)" >&2
  exit 2
fi

case "${STEVE_KEY_EXCHANGE:-}" in
  X25519|XWING-DRAFT10) ;;
  *)
    echo "STEVE_KEY_EXCHANGE must be explicitly set to X25519 or XWING-DRAFT10" >&2
    exit 2
    ;;
esac

case "${STEVE_REMOTE_REQUIRE_NONZERO_PCRS:-0}" in
  0|1) ;;
  *)
    echo "STEVE_REMOTE_REQUIRE_NONZERO_PCRS must be exactly 0 or 1" >&2
    exit 2
    ;;
esac

if [ -n "${STEVE_E2E_BROWSER:-}" ]; then
  npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e:nitro
elif [ -d "/Applications/Google Chrome.app" ]; then
  STEVE_E2E_BROWSER_CHANNEL=chrome \
    npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e:nitro
else
  npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e:nitro
fi
