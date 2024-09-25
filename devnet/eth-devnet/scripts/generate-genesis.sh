#!/bin/bash

set -exu
set -o pipefail

cd "$(dirname "$0")"

PRYSM_CTL=../prysmctl-v5.1.0-linux-amd64

$PRYSM_CTL testnet generate-genesis --fork deneb --num-validators 2 --genesis-time-delay 15 --chain-config-file ./config.yml --geth-genesis-json-in ./genesis.json.template  --geth-genesis-json-out ./genesis.prysm.json --output-ssz ./genesis.ssz

cp genesis.prysm.json genesis.ssz ../node1/data
cp genesis.prysm.json genesis.ssz ../node2/data
