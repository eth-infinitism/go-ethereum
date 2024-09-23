#!/bin/bash

set -exu
set -o pipefail

cd "$(dirname "$0")"
cd ..

docker-compose kill node1 node2
sudo rm -rf node{1,2}/data/*
rm ./scripts/genesis.ssz ./scripts/genesis.prysm.json
