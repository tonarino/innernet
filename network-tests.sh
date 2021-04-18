#!/usr/bin/env bash
set -ex

tmp_dir=$(mktemp -d -t innernet-tests-XXXXXXXXXX)
cleanup() {
    rm -rf "$tmp_dir"
    docker stop $(docker ps -q)
    docker network remove innernet
}
trap cleanup EXIT

if [[ "$OSTYPE" == "darwin"* ]]; then
    # load WireGuard's kernel module is loaded in the macOS Docker VM.
    docker run --rm --pid=host --privileged justincormack/nsenter1 /sbin/modprobe wireguard
fi

NETWORK=$(docker network create -d bridge --subnet=172.18.0.0/16 innernet)
SERVER_CONTAINER=$(docker run -itd --rm --network "$NETWORK" --ip 172.18.1.1 --cap-add NET_ADMIN innernet-server)

echo "waiting for server to initialize..."
sleep 10

docker cp "$SERVER_CONTAINER:/app/peer1.toml" "$tmp_dir"
PEER1_CONTAINER=$(docker create --rm -it --network "$NETWORK" --ip 172.18.1.2 --cap-add NET_ADMIN innernet)

docker cp "$tmp_dir/peer1.toml" "$PEER1_CONTAINER:/app/"
docker start -i "$PEER1_CONTAINER"

echo "created network $NETWORK and server container $SERVER_CONTAINER"
