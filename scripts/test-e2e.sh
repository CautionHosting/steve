#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMPOSE_FILE="$ROOT_DIR/tests/e2e/compose.yaml"
PROJECT_NAME=steve-e2e
ACTION=${1:-test}
REQUESTED_KEY_EXCHANGE=${STEVE_KEY_EXCHANGE:-}
STEVE_KEY_EXCHANGE=${REQUESTED_KEY_EXCHANGE:-X25519}
STEVE_ALLOW_PLAINTEXT_FALLBACK=${STEVE_ALLOW_PLAINTEXT_FALLBACK:-false}
SERVICES_RUNNING=0
SWIFT_BUILD_DIR="$ROOT_DIR/target/steve-sdk-uniffi-smoke"
SWIFT_CARGO_TARGET_DIR="$SWIFT_BUILD_DIR/cargo"
SWIFT_BINDGEN_TARGET_DIR="$ROOT_DIR/target/steve-sdk-uniffi-tools"
SWIFT_BINDINGS_DIR="$SWIFT_BUILD_DIR/swift"
SWIFT_SMOKE_BINARY="$SWIFT_BUILD_DIR/steve-sdk-swift-smoke"

validate_key_exchange() {
  case "$1" in
    X25519|XWING-DRAFT10) ;;
    *)
      echo "STEVE_KEY_EXCHANGE must be exactly X25519 or XWING-DRAFT10" >&2
      exit 2
      ;;
  esac
}

if [ "$ACTION" != swift ]; then
  validate_key_exchange "$STEVE_KEY_EXCHANGE"
fi
case "$STEVE_ALLOW_PLAINTEXT_FALLBACK" in
  true|false) ;;
  *)
    echo "STEVE_ALLOW_PLAINTEXT_FALLBACK must be exactly true or false" >&2
    exit 2
    ;;
esac
export STEVE_KEY_EXCHANGE
export STEVE_ALLOW_PLAINTEXT_FALLBACK

compose() {
  docker compose --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE" "$@"
}

build_assets() {
  make -C "$ROOT_DIR/steve-js-sdk" build-test-assets
}

build_swift_smoke() {
  if ! command -v swiftc >/dev/null 2>&1 || ! command -v xcrun >/dev/null 2>&1; then
    echo "make test-swift requires the macOS Command Line Tools" >&2
    return 1
  fi
  mkdir -p "$SWIFT_BINDINGS_DIR" "$SWIFT_BUILD_DIR/module-cache" \
    "$SWIFT_BUILD_DIR/sdk-module-cache"

  swift_target=$(swiftc -print-target-info | sed -n \
    's/.*"triple": "\([^"]*\)".*/\1/p')
  if [ -z "$swift_target" ]; then
    echo "swiftc did not report a target triple" >&2
    return 1
  fi
  compiler_deployment_target=${swift_target##*macosx}
  deployment_target=${MACOSX_DEPLOYMENT_TARGET:-$compiler_deployment_target}
  echo "Building Swift UniFFI library, bindings, and smoke executable"
  MACOSX_DEPLOYMENT_TARGET=$deployment_target \
    cargo build --release --locked --manifest-path "$ROOT_DIR/Cargo.toml" \
      --target-dir "$SWIFT_CARGO_TARGET_DIR" \
      -p steve-sdk-uniffi --features synthetic-testing --lib
  cargo build --release --locked --manifest-path "$ROOT_DIR/Cargo.toml" \
    --target-dir "$SWIFT_BINDGEN_TARGET_DIR" \
    -p steve-sdk-uniffi --features bindgen --bin uniffi-bindgen-swift

  "$SWIFT_BINDGEN_TARGET_DIR/release/uniffi-bindgen-swift" \
    --metadata-no-deps \
    --module-name SteveSDKFFI \
    --modulemap-filename SteveSDKFFI.modulemap \
    --swift-sources --headers --modulemap \
    "$SWIFT_CARGO_TARGET_DIR/release/libsteve_sdk_uniffi.a" \
    "$SWIFT_BINDINGS_DIR"

  set --
  sdk_path=$(xcrun --show-sdk-path)
  case "$(uname -m)" in
    arm64) swift_interface_arch=arm64e ;;
    *) swift_interface_arch=x86_64 ;;
  esac
  swift_interface="$sdk_path/usr/lib/swift/Swift.swiftmodule/$swift_interface_arch-apple-macos.swiftinterface"
  if [ -f "$swift_interface" ]; then
    interface_version=$(sed -n \
      's/.*-user-module-version \([^ ]*\).*/\1/p' "$swift_interface")
    if [ -n "$interface_version" ]; then
      set -- -interface-compiler-version "$interface_version"
    fi
  fi

  swiftc -parse-as-library \
    -target "$(uname -m)-apple-macosx$deployment_target" \
    -module-cache-path "$SWIFT_BUILD_DIR/module-cache" \
    -sdk-module-cache-path "$SWIFT_BUILD_DIR/sdk-module-cache" \
    "$@" \
    -I "$SWIFT_BINDINGS_DIR" \
    -Xcc -fmodule-map-file="$SWIFT_BINDINGS_DIR/SteveSDKFFI.modulemap" \
    "$SWIFT_BINDINGS_DIR/SteveSDK.swift" \
    "$ROOT_DIR/crates/steve-sdk-uniffi/tests/swift/Smoke.swift" \
    "$SWIFT_CARGO_TARGET_DIR/release/libsteve_sdk_uniffi.a" \
    -o "$SWIFT_SMOKE_BINARY"
  echo "Built Swift smoke executable"
}

prepare() {
  build_assets
  compose build
}

prepare_swift() {
  echo "Building signed synthetic STEVE and upstream fixture images"
  echo "  Docker progress is hidden; a cold build may take a few minutes"
  compose build --quiet
}

wait_for_services() {
  attempts=0
  until curl --fail --silent http://127.0.0.1:3000/local/ >/dev/null \
    && [ "$(curl --silent --output /dev/null --write-out '%{http_code}' \
      --request POST \
      --header 'Content-Type: application/cbor' \
      --data-binary 'not-cbor' \
      http://127.0.0.1:49500/e2p/v2/session || true)" = "400" ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 90 ]; then
      compose logs
      echo "STEVE E2E services did not become ready" >&2
      return 1
    fi
    sleep 1
  done
}

start_suite() {
  STEVE_KEY_EXCHANGE=$1
  STEVE_ALLOW_PLAINTEXT_FALLBACK=$2
  export STEVE_KEY_EXCHANGE
  export STEVE_ALLOW_PLAINTEXT_FALLBACK
  SERVICES_RUNNING=1
  compose up --detach --no-build --force-recreate
  wait_for_services
  echo "  READY signed synthetic STEVE: $STEVE_KEY_EXCHANGE"
}

stop() {
  compose down --timeout "${1:-10}" --volumes --remove-orphans
  SERVICES_RUNNING=0
}

cleanup_test() {
  status=$?
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ] && [ "$SERVICES_RUNNING" -eq 1 ]; then
    echo "STEVE E2E failed; container logs follow:" >&2
    compose logs --no-color --tail 200 >&2 || true
  fi
  if [ "$SERVICES_RUNNING" -eq 1 ]; then
    if [ "$ACTION" = swift ]; then
      stop 1 || true
    else
      stop || true
    fi
  fi
  exit "$status"
}

run_playwright() {
  if [ -n "${STEVE_E2E_BROWSER:-}" ]; then
    STEVE_E2E_PROFILE=local npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e
  elif [ -d "/Applications/Google Chrome.app" ]; then
    STEVE_E2E_PROFILE=local \
    STEVE_E2E_BROWSER_CHANNEL=chrome \
      npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e
  else
    STEVE_E2E_PROFILE=local npm --prefix "$ROOT_DIR/steve-js-sdk" run test:e2e
  fi
}

run_native_sdk() {
  STEVE_E2E_URL=http://127.0.0.1:49500 \
    cargo test --locked --manifest-path "$ROOT_DIR/Cargo.toml" \
      -p steve-sdk --lib tests::external_eval_e2e \
      -- --exact --ignored --nocapture
}

run_suite() {
  suite=$1
  echo "Running STEVE E2E suite: $suite"
  start_suite "$suite" false
  bootstrap_response=$(curl --fail --silent http://127.0.0.1:49500/)
  if [ "$bootstrap_response" != "steve nitro test app" ]; then
    echo "default bootstrap response differed from the upstream" >&2
    return 1
  fi
  plaintext_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    http://127.0.0.1:49500/plaintext-probe)
  if [ "$plaintext_status" != "403" ]; then
    echo "plaintext request returned HTTP $plaintext_status; expected 403" >&2
    return 1
  fi
  upstream_count=$(curl --fail --silent \
    'http://127.0.0.1:3000/__steve_e2e_upstream_count?method=GET&path=/plaintext-probe')
  if [ "$upstream_count" -ne 0 ]; then
    echo "plaintext request reached the upstream $upstream_count time(s)" >&2
    return 1
  fi
  run_playwright
  run_native_sdk
  stop
}

run_plaintext_compatibility() {
  echo "Running explicit plaintext fallback compatibility probe"
  start_suite X25519 true
  response=$(curl --fail --silent http://127.0.0.1:49500/health)
  if [ "$response" != "ok" ]; then
    echo "plaintext compatibility response differed from the upstream" >&2
    return 1
  fi
  stop
}

run_swift() {
  if [ -n "$REQUESTED_KEY_EXCHANGE" ]; then
    echo "make test-swift always runs X25519 and XWING-DRAFT10; ignoring STEVE_KEY_EXCHANGE"
  fi
  build_swift_smoke
  prepare_swift

  echo "Running Swift UniFFI smoke: X25519 pinned"
  start_suite X25519 false
  "$SWIFT_SMOKE_BINARY" pinned-x25519
  stop 1

  echo "Running Swift UniFFI smoke: XWING-DRAFT10 TOFU"
  start_suite XWING-DRAFT10 false
  "$SWIFT_SMOKE_BINARY" tofu-xwing
  stop 1

  echo "PASS Swift UniFFI smoke: both suites"
}

case "$ACTION" in
  test)
    trap cleanup_test EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    prepare
    if [ -n "$REQUESTED_KEY_EXCHANGE" ]; then
      run_suite "$REQUESTED_KEY_EXCHANGE"
    else
      for suite in X25519 XWING-DRAFT10; do
        run_suite "$suite"
      done
    fi
    run_plaintext_compatibility
    ;;
  swift)
    trap cleanup_test EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    run_swift
    ;;
  up)
    prepare
    start_suite "$STEVE_KEY_EXCHANGE" "$STEVE_ALLOW_PLAINTEXT_FALLBACK"
    echo "STEVE local synthetic UI: http://127.0.0.1:3000/local/"
    echo "STEVE production Nitro UI: http://127.0.0.1:3000/nitro/"
    ;;
  down)
    stop
    ;;
  logs)
    compose logs --follow --tail 100
    ;;
  *)
    echo "usage: $0 [test|swift|up|down|logs]" >&2
    exit 2
    ;;
esac
