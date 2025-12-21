#!/bin/bash
set -e

cd "$(dirname "$0")"

CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"

echo "Building service worker bundle..."
$CONTAINER_ENGINE build -t enclave-service-worker-build .

echo "Extracting built files..."
container_id=$($CONTAINER_ENGINE create enclave-service-worker-build)
mkdir -p dist
$CONTAINER_ENGINE cp "$container_id:/" - | tar -xf - -C dist --strip-components=1
$CONTAINER_ENGINE rm "$container_id" > /dev/null

echo "Build complete. Files in dist/"
ls -la dist/
