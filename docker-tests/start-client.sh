#!/bin/bash
set -e

DEFAULT_ARGS="--backend userspace"

INTERFACE="${INTERFACE:-innernet}"
innernet $DEFAULT_ARGS install \
    --name "$INTERFACE" \
    --delete-invite \
    --no-write-hosts \
    /app/invite.toml

while true; do
    innernet $DEFAULT_ARGS up --no-write-hosts "$INTERFACE"
    sleep 1
done
