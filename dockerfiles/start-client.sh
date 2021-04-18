#!/bin/bash
set -e

innernet install \
    --name "evilcorp1" \
    --delete-invite \
    --no-write-hosts \
    /app/peer1.toml

innernet up evilcorp1

ping -c 5 10.66.0.1
sleep infinity &
wait
