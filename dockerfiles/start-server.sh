#!/bin/bash
set -e

innernet-server new \
    --network-name "evilcorp" \
    --network-cidr "10.66.0.0/16" \
    --external-endpoint "172.18.1.1:51820" \
    --listen-port 51820

innernet-server add-cidr evilcorp --name "humans" --cidr "10.66.1.0/24" --parent "evilcorp" --force

innernet-server add-peer evilcorp --name "admin" --cidr "humans" --admin true --auto-ip --save-config "peer1.toml" --force

innernet-server serve evilcorp
