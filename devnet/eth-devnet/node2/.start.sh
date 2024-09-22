#!/bin/bash

# Initialize Geth
./geth --datadir /data/geth init /data/genesis.prysm.json

# Generate JWT secret if it doesn't exist
mkdir -p /data/geth/geth
mkdir -p /data/logs
if [ ! -f /data/geth/geth/jwtsecret ]; then
  openssl rand -hex 32 | tr -d "\n" > /data/geth/geth/jwtsecret
fi

cp /app/nodekey /data/geth/geth/nodekey
cp /app/config.toml /data/geth/

# Start Geth Execution Node
./geth --networkid 1337 \
  --http \
  --config config.toml \
  --http.api eth,net,web3,engine,admin \
  --http.addr 0.0.0.0 \
  --http.corsdomain "*" \
  --http.port 8547 \
  --port 30304 \
  --metrics \
  --metrics.addr 0.0.0.0 \
  --metrics.port 6061 \
  --ws \
  --ws.api eth,net,web3 \
  --ws.addr 0.0.0.0 \
  --ws.origins "*" \
  --ws.port 8548 \
  --authrpc.vhosts "*" \
  --authrpc.addr 0.0.0.0 \
  --authrpc.jwtsecret /data/geth/geth/jwtsecret \
  --authrpc.port 8553 \
  --datadir /data/geth \
  --identity node-2 \
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
  --peer "/ip4/172.20.0.2/tcp/13000/p2p/16Uiu2HAmNYTUE5jNA1MidN53yaojJU22JKRnfDTRvudkeb7pUXTx" \
  --peer "/ip4/172.20.0.2/udp/12000/p2p/16Uiu2HAmNYTUE5jNA1MidN53yaojJU22JKRnfDTRvudkeb7pUXTx" \
  --interop-eth1data-votes \
  --chain-config-file /app/config.yml \
  --contract-deployment-block 0 \
  --chain-id 1337 \
  --rpc-host 0.0.0.0 \
  --rpc-port 4001 \
  --grpc-gateway-host 0.0.0.0 \
  --grpc-gateway-port 3501 \
  --execution-endpoint http://localhost:8553 \
  --accept-terms-of-use \
  --jwt-secret /data/geth/geth/jwtsecret \
  --suggested-fee-recipient 0x123463A4B065722E99115D6C222F267D9CABB524 \
  --minimum-peers-per-subnet 0 \
  --p2p-tcp-port 13001 \
  --p2p-udp-port 12001 \
  --monitoring-port 8082 \
  --verbosity debug \
  --slasher \
  --enable-debug-rpc-endpoints > /data/logs/beacon.log 2>&1 &

# Wait for Beacon Node to start
sleep 5

# Start Prysm Validator Client
./validator-v5.1.0-linux-amd64 \
  --beacon-rpc-provider localhost:4001 \
  --datadir /data/validator \
  --accept-terms-of-use \
  --interop-num-validators 1 \
  --interop-start-index 1 \
  --rpc-port 7001 \
  --grpc-gateway-port 7501 \
  --monitoring-port 8083 \
  --graffiti "node-2" \
  --chain-config-file /app/config.yml > /data/logs/validator.log 2>&1 &

# Start Bundler
#echo "Starting Bundler..."
#cd /app/bundler/bundler
#yarn bundler-rip7560 > /data/logs/bundler.log 2>&1 &

# Keep the container running
tail -f /dev/null
