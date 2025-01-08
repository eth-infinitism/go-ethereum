#!/bin/bash

set -exu
set -o pipefail

cd "$(dirname "$0")"

GETH_BOOTNODE=../node1/bootnode
PRYSM_BIN=../node1/beacon-chain-v5.1.0-linux-amd64

if [[ ! -f "nodekey" ]]; then
  $GETH_BOOTNODE -genkey nodekey
fi
#$GETH_BOOTNODE -nodekey nodekey -addr 0.0.0.0:$GETH_BOOTNODE_PORT -verbosity=5 > "bootnode.log" 2>&1
if [[ ! -f "network-keys" ]]; then
   $PRYSM_BIN --p2p-static-id  --chain-id 1337 --datadir ./ --accept-terms-of-use
fi
