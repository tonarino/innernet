#!/usr/bin/env bash

set -e

cmd() {
  echo "[#] $*" >&2
  "$@"
}

if [ $# -lt 2 ]; then
  echo "Usage: $0 distro version (from docker hub), e.g:"
  echo
  echo "$0 fedora 33"
  exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"

cd $SCRIPT_DIR/..


echo "will pull from docker $1:$2"
docker build --tag innernet-rpm-builder --file rpm/Dockerfile --build-arg DISTRO="$1" --build-arg VER="$2" .

mkdir -p target/rpm

echo "exporting built rpm's from docker image"
CONTAINER_ID="$(docker create innernet-rpm-builder -v)"
docker export $CONTAINER_ID | tar xC target/rpm *.rpm

echo "cleaning up"
docker container rm $CONTAINER_ID
docker image prune --force --filter label=stage=innernet-rpm-builder
docker image rm innernet-rpm-builder
