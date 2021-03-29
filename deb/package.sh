#!/usr/bin/env bash

set -e

SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"
cd $SCRIPT_DIR/../client

if ! cargo install --list | grep cargo-deb > /dev/null; then
  cargo install cargo-deb
fi

set -x

cargo build --release
cargo deb --package client --no-build
