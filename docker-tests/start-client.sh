#!/bin/bash
set -e

INTERFACE="${INTERFACE:-innernet}"
innernet install \
    --name "$INTERFACE" \
    --delete-invite \
    --no-write-hosts \
    /app/invite.toml

while true; do
    innernet up --no-write-hosts "$INTERFACE"
    sleep 1
done
