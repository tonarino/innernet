#!/usr/bin/env bash
set -e

echo "INFO: This script generate TS binding from Rust and CP them to /ui"

# Set to script dir (/ui)
dir=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

# Generate bindings
cd "$(dirname "$dir")/shared"
cargo test

# Copy Bindings
echo "INFO: Cleaning old bindings & Copying new ones"
rm -rf "$dir/src/model/shared/*"
cp -a "$PWD/bindings/." "$dir/src/model/shared"

echo "INFO: DONE - Bindings should be in /ui/model/shared/"