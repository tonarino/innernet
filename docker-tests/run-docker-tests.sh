#!/usr/bin/env bash
set -e
shopt -s nocasematch

SELF_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$SELF_DIR/.."

help() {
    cat >&2 <<-_EOF
Usage: "${0##*/}" [options...] (<test>)
 --userspace  Use userspace wireguard instead of kernel one
 --verbose    Print verbose innernet logs
_EOF
}

TEST_FILTER=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --userspace)
        INNERNET_ARGS="$INNERNET_ARGS --backend userspace"
        shift
        ;;
    --verbose)
        INNERNET_ARGS="$INNERNET_ARGS -vvv"
        CLIENT_ARGS="$CLIENT_ARGS --verbose"
        SERVER_RUST_LOG="debug"
        CLIENT_RUST_LOG="trace"
        shift
        ;;
    --help)
        help
        exit
        ;;
    -*)
        echo "Invalid option."
        help
        exit 1
        ;;
    *)
        TEST_FILTER+=("$1")
        shift
        ;;
  esac
done

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
    --env RUST_LOG="$SERVER_RUST_LOG" \
    --env INNERNET_ARGS="$INNERNET_ARGS" \
    --cap-add NET_ADMIN \
    innernet)
cmd docker start -a "$SERVER_CONTAINER" | sed -e 's/^/\x1B[0;95mserver\x1B[0m: /' &

info "server started as $SERVER_CONTAINER"
info "Waiting for server to initialize."
cmd sleep 5

create_peer_docker() {
    local IP=$1
    cmd docker create --rm -it \
        --network "$NETWORK" \
        --ip $IP \
        --volume /dev/net/tun:/dev/net/tun \
        --cap-add NET_ADMIN \
        --env RUST_LOG="$CLIENT_RUST_LOG" \
        --env INTERFACE=evilcorp \
        --env INNERNET_ARGS="$INNERNET_ARGS" \
        --env CLIENT_ARGS="$CLIENT_ARGS" \
        innernet /app/start-client.sh
}

info "Starting first peer."
cmd docker cp "$SERVER_CONTAINER:/app/peer1.toml" "$tmp_dir"
PEER1_CONTAINER=$(create_peer_docker 172.18.1.2)
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
PEER2_CONTAINER=$(create_peer_docker 172.18.1.3)
info "peer2 started as $PEER2_CONTAINER"
cmd docker cp "$tmp_dir/peer2.toml" "$PEER2_CONTAINER:/app/invite.toml"
cmd docker start -a "$PEER2_CONTAINER" | sed -e 's/^/\x1B[0;93mpeer 2\x1B[0m: /' &
sleep 10

test_short_lived_invitation() {
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
}

test_simultaneous_redemption() {
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
    PEER4_CONTAINER=$(create_peer_docker 172.18.1.4)
    cmd docker cp "$tmp_dir/peer4.toml" "$PEER4_CONTAINER:/app/invite.toml"
    PEER5_CONTAINER=$(create_peer_docker 172.18.1.5)
    cmd docker cp "$tmp_dir/peer5.toml" "$PEER5_CONTAINER:/app/invite.toml"

    cmd docker start -a "$PEER4_CONTAINER" | sed -e 's/^/\x1B[0;92mpeer 4\x1B[0m: /' &
    info "peer4 started as $PEER4_CONTAINER"
    cmd docker start -a "$PEER5_CONTAINER" | sed -e 's/^/\x1B[0;94mpeer 5\x1B[0m: /' &
    info "peer5 started as $PEER5_CONTAINER"

    info "Checking connectivity betweeen peers."
    cmd docker exec "$PEER2_CONTAINER" ping -c3 10.66.0.1
    cmd docker exec "$PEER2_CONTAINER" ping -c3 10.66.1.1
}

# Run tests (functions prefixed with test_) in alphabetical order.
# Optional filter provided by positional arguments is applied.
for func in $(declare -F | awk '{print $3}'); do
    if [[ "$func" =~ ^test_ ]]; then
        if [ ${#TEST_FILTER[@]} -eq 0 ] || [[ "${TEST_FILTER[*]}" =~ "$func" ]]; then
            $func
        fi
    fi
done

echo
info "Test succeeded."
