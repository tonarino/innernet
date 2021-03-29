#!/usr/bin/env bash

info() {
  TERM=${TERM:-dumb} echo -e "$(tput setaf 4)- $@$(tput sgr0)" 1>&2
}

cmd() {
  echo "[#] $*" >&2
  "$@"
}

if [ $# -lt 2 ]; then
  echo "Usage: $0 bootstrap_conf interface_name"
  exit 1
fi

set -e

conf="$1"
name="$2"

info "installing wireguard config file."
cmd sudo mv $conf /etc/wireguard/$name.conf
cmd sudo chown root:root /etc/wireguard/$name.conf
cmd sudo chmod 600 /etc/wireguard/$name.conf

info "enabling innernet service."
cmd sudo systemctl enable innernet@$name
cmd sudo systemctl start innernet@$name
