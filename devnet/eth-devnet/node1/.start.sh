#!/bin/bash

# Initialize Geth
./geth --datadir /data/geth init /data/genesis.prysm.json

# Generate JWT secret if it doesn't exist
mkdir -p /data/geth/geth
mkdir -p /data/logs
if [ ! -f /data/geth/geth/jwtsecret ]; then
  openssl rand -hex 32 | tr -d "\n" > /data/geth/geth/jwtsecret
fi

# Copy nodekey and config.toml into data directory
cp /app/nodekey /data/geth/geth/nodekey
cp /app/config.toml /data/geth/

# Start Geth Execution Node
./geth --networkid 1337 \
  --config config.toml \
  --http \
  --http.api eth,net,web3,engine,admin \
  --http.addr 0.0.0.0 \
  --http.corsdomain "*" \
  --http.port 8545 \
  --port 30303 \
  --metrics \
  --metrics.addr 0.0.0.0 \
  --metrics.port 6060 \
  --ws \
  --ws.api eth,net,web3 \
  --ws.addr 0.0.0.0 \
  --ws.origins "*" \
  --ws.port 8546 \
  --authrpc.vhosts "*" \
  --authrpc.addr 0.0.0.0 \
  --authrpc.jwtsecret /data/geth/geth/jwtsecret \
  --authrpc.port 8551 \
  --datadir /data/geth \
  --identity node-1 \
  --maxpendpeers 2 \
  --verbosity 3 \
  --syncmode full > /data/logs/geth.log 2>&1 &

# Wait for Geth to start
sleep 5

# Start Prysm Beacon Node (key generated with --p2p-static-id)
./beacon-chain-v5.1.0-linux-amd64 \
  --datadir /data/beacon \
  --min-sync-peers 1 \
  --p2p-priv-key /app/beaconkey \
  --genesis-state /data/genesis.ssz \
  --bootstrap-node "" \
  --peer "/ip4/172.20.0.3/tcp/13001/p2p/16Uiu2HAmFz274W7rTgaeoifJwmtsRn9KVkvrvAmfNvg9gdhw89Gg" \
  --peer "/ip4/172.20.0.3/udp/12001/p2p/16Uiu2HAmFz274W7rTgaeoifJwmtsRn9KVkvrvAmfNvg9gdhw89Gg" \
  --interop-eth1data-votes \
  --chain-config-file /app/config.yml \
  --contract-deployment-block 0 \
  --chain-id 1337 \
  --rpc-host 0.0.0.0 \
  --rpc-port 4000 \
  --grpc-gateway-host 0.0.0.0 \
  --grpc-gateway-port 3500 \
  --execution-endpoint http://localhost:8551 \
  --accept-terms-of-use \
  --jwt-secret /data/geth/geth/jwtsecret \
  --suggested-fee-recipient 0x123463A4B065722E99115D6C222F267D9CABB524 \
  --minimum-peers-per-subnet 0 \
  --p2p-tcp-port 13000 \
  --p2p-udp-port 12000 \
  --monitoring-port 8080 \
  --verbosity debug \
  --slasher \
  --enable-debug-rpc-endpoints > /data/logs/beacon.log 2>&1 &

# Wait for Beacon Node to start
sleep 5

# Start Prysm Validator Client
./validator-v5.1.0-linux-amd64 \
  --beacon-rpc-provider localhost:4000 \
  --datadir /data/validator \
  --accept-terms-of-use \
  --interop-num-validators 1 \
  --interop-start-index 0 \
  --rpc-port 7000 \
  --grpc-gateway-port 7500 \
  --monitoring-port 8081 \
  --graffiti "node-1" \
  --chain-config-file /app/config.yml > /data/logs/validator.log 2>&1 &

# Start Bundler
#echo "Starting Bundler..."
#cd /app/bundler/bundler
#yarn bundler-rip7560 > /data/logs/bundler.log 2>&1 &

# Keep the container running
tail -f /dev/null
