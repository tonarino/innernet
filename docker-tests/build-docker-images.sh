#!/usr/bin/env bash
set -ex

SELF_DIR="$(dirname "$0")"
cd "$SELF_DIR/.."

docker build -t innernet-server -f "$SELF_DIR/Dockerfile.innernet-server" .
docker build -t innernet -f "$SELF_DIR/Dockerfile.innernet" .
