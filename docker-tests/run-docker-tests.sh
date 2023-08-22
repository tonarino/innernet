#!/usr/bin/env bash
set -e
shopt -s nocasematch

SELF_DIR="$(dirname "$0")"
cd "$SELF_DIR/.."

if [[ $# -eq 1 ]]; then
    case "$1" in
        kernel)
            INNERNET_ARGS="-vvv"
            ;;
        userspace)
            INNERNET_ARGS="-vvv --backend userspace"
            ;;
        *)
            echo "invalid backend (must be kernel or userspace)"
            exit 1
    esac
else
    cat >&2 <<-_EOF
    Usage: "${0##*/}" <BACKEND>

    BACKEND: "kernel" or "userspace"
_EOF
    exit
fi

cmd() {
	echo "[#] $*" >&2
	"$@"
}

info() {
  echo -e "\033[0;34m- $@\033[0m" 1>&2
}

tmp_dir=$(mktemp -d -t innernet-tests-XXXXXXXXXX)
info "temp dir: $tmp_dir"
cleanup() {
    info "Cleaning up."
    rm -rf "$tmp_dir"
    cmd docker stop $(docker ps -q) || true
    cmd docker network remove innernet
}
trap cleanup EXIT

info "Creating network."
NETWORK=$(cmd docker network create -d bridge --subnet=172.18.0.0/16 innernet)

info "Starting server."
SERVER_CONTAINER=$(cmd docker create -it --rm \
    --network "$NETWORK" \
    --ip 172.18.1.1 \
    --volume /dev/net/tun:/dev/net/tun \
    --env RUST_LOG=debug \
    --env INNERNET_ARGS="$INNERNET_ARGS" \
    --cap-add NET_ADMIN \
    innernet)
cmd docker start -a "$SERVER_CONTAINER" | sed -e 's/^/\x1B[0;95mserver\x1B[0m: /' &

info "server started as $SERVER_CONTAINER"
info "Waiting for server to initialize."
cmd sleep 5

info "Starting first peer."
cmd docker cp "$SERVER_CONTAINER:/app/peer1.toml" "$tmp_dir"
PEER1_CONTAINER=$(cmd docker create --rm -it \
    --network "$NETWORK" \
    --ip 172.18.1.2 \
    --volume /dev/net/tun:/dev/net/tun \
    --env INTERFACE=evilcorp \
    --env RUST_LOG=trace \
    --env INNERNET_ARGS="$INNERNET_ARGS" \
    --cap-add NET_ADMIN \
    innernet /app/start-client.sh)
info "peer1 started as $PEER1_CONTAINER"
cmd docker cp "$tmp_dir/peer1.toml" "$PEER1_CONTAINER:/app/invite.toml"
cmd docker start -a "$PEER1_CONTAINER" | sed -e 's/^/\x1B[0;96mpeer 1\x1B[0m: /' &
sleep 10

info "Creating a new CIDR from first peer."
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-cidr evilcorp \
    --name "robots" \
    --cidr "10.66.2.0/24" \
    --parent "evilcorp" \
    --yes

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
    --invite-expires "30s" \
    --yes
cmd docker cp "$PEER1_CONTAINER:/app/peer2.toml" "$tmp_dir"

info "Starting second peer."
PEER2_CONTAINER=$(docker create --rm -it \
    --network "$NETWORK" \
    --ip 172.18.1.3 \
    --volume /dev/net/tun:/dev/net/tun \
    --cap-add NET_ADMIN \
    --env INTERFACE=evilcorp \
    --env INNERNET_ARGS="$INNERNET_ARGS" \
    innernet /app/start-client.sh)
info "peer2 started as $PEER2_CONTAINER"
cmd docker cp "$tmp_dir/peer2.toml" "$PEER2_CONTAINER:/app/invite.toml"
cmd docker start -a "$PEER2_CONTAINER" | sed -e 's/^/\x1B[0;93mpeer 2\x1B[0m: /' &
sleep 10

info "Creating short-lived invitation for third peer."
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-peer evilcorp \
    --name "peer3" \
    --cidr "robots" \
    --admin false \
    --ip "10.66.2.100" \
    --save-config "/app/peer3.toml" \
    --invite-expires "1s" \
    --yes

info "waiting 15 seconds to see if the server clears out the IP address."
sleep 11

info "Re-requesting invite after expiration with the same parameters."
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-peer evilcorp \
    --name "peer3" \
    --cidr "robots" \
    --admin false \
    --ip "10.66.2.100" \
    --save-config "/app/peer3_2.toml" \
    --invite-expires "30m" \
    --yes

info "peer2 started as $PEER2_CONTAINER"
cmd docker cp "$tmp_dir/peer2.toml" "$PEER2_CONTAINER:/app/invite.toml"
cmd docker start -a "$PEER2_CONTAINER" | sed -e 's/^/\x1B[0;93mpeer 2\x1B[0m: /' &
sleep 10

info "Creating invitation for fourth and fifth peer from first peer."
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-peer evilcorp \
    --name "peer4" \
    --cidr "robots" \
    --admin false \
    --auto-ip \
    --save-config "/app/peer4.toml" \
    --invite-expires "30s" \
    --yes
cmd docker cp "$PEER1_CONTAINER:/app/peer4.toml" "$tmp_dir"
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-peer evilcorp \
    --name "peer5" \
    --cidr "robots" \
    --admin false \
    --auto-ip \
    --save-config "/app/peer5.toml" \
    --invite-expires "30s" \
    --yes
cmd docker cp "$PEER1_CONTAINER:/app/peer5.toml" "$tmp_dir"

info "Starting fourth and fifth peer and redeeming simultaneously."
PEER4_CONTAINER=$(docker create --rm -it \
    --network "$NETWORK" \
    --ip 172.18.1.4 \
    --volume /dev/net/tun:/dev/net/tun \
    --cap-add NET_ADMIN \
    --env INTERFACE=evilcorp \
    --env INNERNET_ARGS="$INNERNET_ARGS" \
    innernet /app/start-client.sh)
cmd docker cp "$tmp_dir/peer4.toml" "$PEER4_CONTAINER:/app/invite.toml"
PEER5_CONTAINER=$(docker create --rm -it \
    --network "$NETWORK" \
    --ip 172.18.1.5 \
    --volume /dev/net/tun:/dev/net/tun \
    --cap-add NET_ADMIN \
    --env INTERFACE=evilcorp \
    --env INNERNET_ARGS="$INNERNET_ARGS" \
    innernet /app/start-client.sh)
cmd docker cp "$tmp_dir/peer5.toml" "$PEER5_CONTAINER:/app/invite.toml"

cmd docker start -a "$PEER4_CONTAINER" | sed -e 's/^/\x1B[0;92mpeer 4\x1B[0m: /' &
info "peer4 started as $PEER4_CONTAINER"
cmd docker start -a "$PEER5_CONTAINER" | sed -e 's/^/\x1B[0;94mpeer 5\x1B[0m: /' &
info "peer5 started as $PEER5_CONTAINER"

info "Checking connectivity betweeen peers."
cmd docker exec "$PEER2_CONTAINER" ping -c3 10.66.0.1
cmd docker exec "$PEER2_CONTAINER" ping -c3 10.66.1.1

echo
info "test succeeded."
