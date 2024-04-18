#!/usr/bin/env bash
set -ex

SELF_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$SELF_DIR/.."

docker build -t innernet -f "$SELF_DIR/Dockerfile.innernet" .
