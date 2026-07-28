#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST_DIR="$ROOT_DIR/steve-js-sdk/dist"
DIST_SNAPSHOT=$(mktemp -d)
trap 'rm -rf -- "$DIST_SNAPSHOT"' EXIT HUP INT TERM

cp -R "$DIST_DIR/." "$DIST_SNAPSHOT/"
make -C "$ROOT_DIR/steve-js-sdk" build
diff -ru "$DIST_SNAPSHOT" "$DIST_DIR"
node "$ROOT_DIR/tests/production/check-exclusions.mjs"
