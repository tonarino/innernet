#!/usr/bin/env bash
set -e

SELF_DIR="$(dirname "$0")"
cd "$SELF_DIR/.."

cmd() {
	echo "[#] $*" >&2
	"$@"
}

info() {
  TERM=${TERM:-dumb} echo -e "$(tput setaf 4)- $@$(tput sgr0)" 1>&2
}

tmp_dir=$(mktemp -d -t innernet-tests-XXXXXXXXXX)
cleanup() {
    info "Cleaning up."
    rm -rf "$tmp_dir"
    cmd docker stop $(docker ps -q)
    cmd docker network remove innernet
}
trap cleanup EXIT

if [[ "$OSTYPE" == "darwin"* ]]; then
    info "Loading wireguard kernel module in Docker VM."
    # ensure the wireguard kernel module is loaded in the macOS docker VM.
    cmd docker run --rm --pid=host --privileged justincormack/nsenter1 /sbin/modprobe wireguard
fi

info "Creating network."
NETWORK=$(cmd docker network create -d bridge --subnet=172.18.0.0/16 innernet)

info "Starting server."
SERVER_CONTAINER=$(cmd docker run -itd --rm \
    --network "$NETWORK" \
    --ip 172.18.1.1 \
    --cap-add NET_ADMIN \
    innernet-server)

info "Waiting for server to initialize."
cmd sleep 10

info "Starting first peer."
cmd docker cp "$SERVER_CONTAINER:/app/peer1.toml" "$tmp_dir"
PEER1_CONTAINER=$(cmd docker create --rm -it \
    --network "$NETWORK" \
    --ip 172.18.1.2 \
    --env INTERFACE=evilcorp \
    --cap-add NET_ADMIN \
    innernet)
cmd docker cp "$tmp_dir/peer1.toml" "$PEER1_CONTAINER:/app/invite.toml"
cmd docker start "$PEER1_CONTAINER"
sleep 5

info "Creating a new CIDR from first peer."
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-cidr evilcorp \
    --name "robots" \
    --cidr "10.66.2.0/24" \
    --parent "evilcorp" \
    --force

info "Creating association between CIDRs."
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-association evilcorp \
        humans \
        robots

info "Creating invitation for second peer from first peer."
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-peer evilcorp \
    --name "peer2" \
    --cidr "robots" \
    --admin false \
    --auto-ip \
    --save-config "/app/peer2.toml" \
    --force
cmd docker cp "$PEER1_CONTAINER:/app/peer2.toml" "$tmp_dir"

info "Starting second peer."
PEER2_CONTAINER=$(docker create --rm -it \
    --network "$NETWORK" \
    --ip 172.18.1.3 \
    --cap-add NET_ADMIN \
    --env INTERFACE=evilcorp \
    innernet)
cmd docker cp "$tmp_dir/peer2.toml" "$PEER2_CONTAINER:/app/invite.toml"
cmd docker start "$PEER2_CONTAINER"
sleep 10

# read -p "Press enter to continue. " -n 1 -r

info "Checking connectivity betweeen peers."
cmd docker exec "$PEER2_CONTAINER" ping -c3 10.66.0.1
cmd docker exec "$PEER2_CONTAINER" ping -c3 10.66.1.1
