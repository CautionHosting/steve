#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

npm --prefix "$ROOT_DIR/steve-js-sdk" run build
node "$ROOT_DIR/tests/production/check-exclusions.mjs"
