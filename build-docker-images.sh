#!/usr/bin/env bash
set -ex

docker build -t innernet-server -f ./dockerfiles/Dockerfile.innernet-server .
docker build -t innernet -f ./dockerfiles/Dockerfile.innernet .
