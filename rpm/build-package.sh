#!/usr/bin/env bash

set -e

cmd() {
  echo "[#] $*" >&2
  "$@"
}

if [ $# -lt 1 ]; then
  echo "Usage: $0 distro version (from docker hub), e.g:"
  echo
  echo "$0 fedora:33"
  exit 1
else
  SPLIT_ARG=(${1//:/ })
  DISTRO=${SPLIT_ARG[0]}
  VER=${SPLIT_ARG[1]}

  if [[ -z "$DISTRO" || -z "$VER" ]]; then
    echo "bad arg"
    exit 1
  fi
fi


SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"
cd $SCRIPT_DIR/..

cmd docker build --tag "innernet-rpm-$DISTRO$VER" --file rpm/Dockerfile --build-arg DISTRO=$DISTRO --build-arg VER=$VER .

echo "exporting built rpm's from docker image"
cmd docker run --rm innernet-rpm-$DISTRO$VER sh -c "tar cf - target/rpm/*" | tar xv

echo "cleaning up"
cmd docker image prune --force --filter label=stage=innernet-rpm
