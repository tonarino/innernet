#!/bin/bash
set -e

INTERFACE="${INTERFACE:-innernet}"
innernet $INNERNET_ARGS install \
    --name "$INTERFACE" \
    --delete-invite \
    --no-write-hosts \
    /app/invite.toml

while true; do
    innernet $INNERNET_ARGS up --no-write-hosts "$INTERFACE"
    sleep 1
done
