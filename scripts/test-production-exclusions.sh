#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST_DIR="$ROOT_DIR/steve-js-sdk/dist"
MODE=${1:-release}

if [ "$#" -gt 1 ]; then
  echo "usage: $0 [fast|release]" >&2
  exit 2
fi

case "$MODE" in
  fast|release) ;;
  *)
    echo "usage: $0 [fast|release]" >&2
    exit 2
    ;;
esac

TMP_ROOT=${TMPDIR:-/tmp}
while [ "${TMP_ROOT%/}" != "$TMP_ROOT" ]; do TMP_ROOT=${TMP_ROOT%/}; done
case "$TMP_ROOT" in
  ""|/)
    echo "TMPDIR must identify a bounded temporary directory" >&2
    exit 2
    ;;
esac

BUILD_ROOT=$(mktemp -d "$TMP_ROOT/steve-production.XXXXXXXX")
FIRST_BUILD="$BUILD_ROOT/first"
SECOND_BUILD="$BUILD_ROOT/second"
trap 'rm -rf -- "$BUILD_ROOT"' EXIT HUP INT TERM

if [ "$MODE" = "fast" ]; then
  echo "Building cached StageX production assets"
  make -C "$ROOT_DIR/steve-js-sdk" build-cached \
    PRODUCTION_OUTPUT="$FIRST_BUILD"
else
  echo "Building first no-cache StageX production artifact"
  make -C "$ROOT_DIR/steve-js-sdk" build \
    PRODUCTION_OUTPUT="$FIRST_BUILD"
fi

diff -ru "$DIST_DIR" "$FIRST_BUILD"

if [ "$MODE" = "release" ]; then
  echo "Building second no-cache StageX production artifact"
  make -C "$ROOT_DIR/steve-js-sdk" build \
    PRODUCTION_OUTPUT="$SECOND_BUILD"
  diff -ru "$FIRST_BUILD" "$SECOND_BUILD"
fi

node "$ROOT_DIR/tests/production/check-exclusions.mjs"
