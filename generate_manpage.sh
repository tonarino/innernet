#!/usr/bin/env bash
set -ex

if ! command -v help2man &> /dev/null
then
    echo "help2man binary could not be found"
    exit
fi

cargo build

for binary in "innernet" "innernet-server"; do
    help2man --no-discard-stderr -s8 "target/debug/$binary" -N > "doc/$binary.8"
    gzip -f "doc/$binary.8"
done
