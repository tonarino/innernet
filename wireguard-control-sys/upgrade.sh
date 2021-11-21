#!/bin/bash -e
# This script modified from https://github.com/rusqlite/rusqlite/blob/master/libsqlite3-sys/upgrade.sh

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CUR_DIR=$(pwd -P)
echo "$SCRIPT_DIR"
cd "$SCRIPT_DIR" || { echo "fatal error" >&2; exit 1; }
cargo clean
mkdir -p "$SCRIPT_DIR/../target"

pushd "$SCRIPT_DIR/c"
curl -O https://raw.githubusercontent.com/WireGuard/wireguard-tools/master/contrib/embeddable-wg-library/wireguard.c
curl -O https://raw.githubusercontent.com/WireGuard/wireguard-tools/master/contrib/embeddable-wg-library/wireguard.h
popd

# Regenerate bindgen file
rm -f "bindgen-bindings/bindings.rs"
# Just to make sure there is only one bindgen.rs file in target dir
find "$SCRIPT_DIR/../target" -type f -name bindings.rs -exec rm {} \;
cargo build --features "buildtime_bindgen"
find "$SCRIPT_DIR/../target" -type f -name bindings.rs -exec mv {} "$SCRIPT_DIR/bindgen-bindings/bindings.rs" \;

# Sanity checks
cd "$SCRIPT_DIR" || { echo "fatal error" >&2; exit 1; }
cargo test
echo 'You should increment the version in Cargo.toml'