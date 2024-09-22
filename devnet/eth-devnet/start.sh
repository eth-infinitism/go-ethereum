#!/bin/bash

set -euo pipefail

# Initialize variables with defaults or environment variables
NETWORK_ID=${NETWORK_ID:-1337}
NODE_IDENTITY=${NODE_IDENTITY:-"node"}
DATA_DIR=${DATA_DIR:-/data}
GENESIS_JSON=${GENESIS_JSON:-/data/genesis.prysm.json}
GENESIS_SSZ=${GENESIS_SSZ:-/data/genesis.ssz}
CONFIG_TOML=${CONFIG_TOML:-/app/config.toml}
CONFIG_YML=${CONFIG_YML:-/app/config.yml}
NODEKEY_PATH=${NODEKEY_PATH:-/app/nodekey}
BEACONKEY_PATH=${BEACONKEY_PATH:-/app/beaconkey}
FEE_RECIPIENT=${FEE_RECIPIENT:-"0x123463A4B065722E99115D6C222F267D9CABB524"}
VALIDATOR_START_INDEX=${VALIDATOR_START_INDEX:-0}

# Ports
HTTP_PORT=${HTTP_PORT:-8545}
WS_PORT=${WS_PORT:-8546}
AUTHRPC_PORT=${AUTHRPC_PORT:-8551}
METRICS_PORT=${METRICS_PORT:-6060}
P2P_PORT=${P2P_PORT:-30303}

BEACON_RPC_PORT=${BEACON_RPC_PORT:-4000}
BEACON_GRPC_PORT=${BEACON_GRPC_PORT:-3500}
BEACON_P2P_TCP_PORT=${BEACON_P2P_TCP_PORT:-13000}
BEACON_P2P_UDP_PORT=${BEACON_P2P_UDP_PORT:-12000}
BEACON_MONITORING_PORT=${BEACON_MONITORING_PORT:-8080}

VALIDATOR_RPC_PORT=${VALIDATOR_RPC_PORT:-7000}
VALIDATOR_GRPC_PORT=${VALIDATOR_GRPC_PORT:-7500}
VALIDATOR_MONITORING_PORT=${VALIDATOR_MONITORING_PORT:-8081}

PEER_NODES=${PEER_NODES:-""}

# Create necessary directories
mkdir -p "$DATA_DIR/geth/geth"
mkdir -p "$DATA_DIR/logs"

# Copy nodekey and config.toml into data directory
cp "$NODEKEY_PATH" "$DATA_DIR/geth/geth/nodekey"
cp "$CONFIG_TOML" "$DATA_DIR/geth/"

# Initialize Geth
./geth --datadir "$DATA_DIR/geth" init "$GENESIS_JSON"

# Generate JWT secret if it doesn't exist
if [ ! -f "$DATA_DIR/geth/geth/jwtsecret" ]; then
  openssl rand -hex 32 | tr -d "\n" > "$DATA_DIR/geth/geth/jwtsecret"
fi

# Start Geth Execution Node
./geth --networkid "$NETWORK_ID" \
  --config "$CONFIG_TOML" \
  --http \
  --http.api eth,net,web3,engine,admin \
  --http.addr 0.0.0.0 \
  --http.corsdomain "*" \
  --http.port "$HTTP_PORT" \
  --port "$P2P_PORT" \
  --metrics \
  --metrics.addr 0.0.0.0 \
  --metrics.port "$METRICS_PORT" \
  --ws \
  --ws.api eth,net,web3 \
  --ws.addr 0.0.0.0 \
  --ws.origins "*" \
  --ws.port "$WS_PORT" \
  --authrpc.vhosts "*" \
  --authrpc.addr 0.0.0.0 \
  --authrpc.jwtsecret "$DATA_DIR/geth/geth/jwtsecret" \
  --authrpc.port "$AUTHRPC_PORT" \
  --datadir "$DATA_DIR/geth" \
  --identity "$NODE_IDENTITY" \
  --maxpendpeers 2 \
  --verbosity 3 \
  --syncmode full > "$DATA_DIR/logs/geth.log" 2>&1 &

# Wait for Geth to start
sleep 5

# Construct --peer flags for Beacon Node
PEER_FLAGS=""
if [ -n "$PEER_NODES" ]; then
  # Split PEER_NODES into an array
  read -ra PEER_ARRAY <<< "$PEER_NODES"
  for PEER in "${PEER_ARRAY[@]}"; do
    PEER_FLAGS+=" --peer $PEER"
  done
fi

# Start Prysm Beacon Node
./beacon-chain-v5.1.0-linux-amd64 \
  --datadir "$DATA_DIR/beacon" \
  --min-sync-peers 1 \
  --p2p-priv-key "$BEACONKEY_PATH" \
  --genesis-state "$GENESIS_SSZ" \
  --bootstrap-node "" \
  $PEER_FLAGS \
  --interop-eth1data-votes \
  --chain-config-file "$CONFIG_YML" \
  --contract-deployment-block 0 \
  --chain-id "$NETWORK_ID" \
  --rpc-host 0.0.0.0 \
  --rpc-port "$BEACON_RPC_PORT" \
  --grpc-gateway-host 0.0.0.0 \
  --grpc-gateway-port "$BEACON_GRPC_PORT" \
  --execution-endpoint http://localhost:"$AUTHRPC_PORT" \
  --accept-terms-of-use \
  --jwt-secret "$DATA_DIR/geth/geth/jwtsecret" \
  --suggested-fee-recipient "$FEE_RECIPIENT" \
  --minimum-peers-per-subnet 0 \
  --p2p-tcp-port "$BEACON_P2P_TCP_PORT" \
  --p2p-udp-port "$BEACON_P2P_UDP_PORT" \
  --monitoring-port "$BEACON_MONITORING_PORT" \
  --verbosity debug \
  --slasher \
  --enable-debug-rpc-endpoints > "$DATA_DIR/logs/beacon.log" 2>&1 &

# Wait for Beacon Node to start
sleep 5

# Start Prysm Validator Client
./validator-v5.1.0-linux-amd64 \
  --beacon-rpc-provider localhost:"$BEACON_RPC_PORT" \
  --datadir "$DATA_DIR/validator" \
  --accept-terms-of-use \
  --interop-num-validators 1 \
  --interop-start-index "$VALIDATOR_START_INDEX" \
  --rpc-port "$VALIDATOR_RPC_PORT" \
  --grpc-gateway-port "$VALIDATOR_GRPC_PORT" \
  --monitoring-port "$VALIDATOR_MONITORING_PORT" \
  --graffiti "$NODE_IDENTITY" \
  --chain-config-file "$CONFIG_YML" > "$DATA_DIR/logs/validator.log" 2>&1 &

# Keep the container running
tail -f /dev/null
