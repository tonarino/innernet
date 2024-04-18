#!/bin/bash
set -e

INTERFACE="${INTERFACE:-innernet}"

innernet $INNERNET_ARGS install \
    --name "$INTERFACE" \
    --delete-invite \
    --no-write-hosts \
    /app/invite.toml

while true; do
    if [[ $CLIENT_ARGS =~ --verbose ]]; then
        innernet $INNERNET_ARGS up --no-write-hosts "$INTERFACE"
    else
        innernet $INNERNET_ARGS up --no-write-hosts "$INTERFACE" > /dev/null
    fi
    sleep 1
done
