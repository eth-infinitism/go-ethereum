FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y software-properties-common wget curl libgomp1 build-essential git gnupg && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js (required for Bundler)
#RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
#    apt-get install -y nodejs && \
#    npm install -g yarn


# Set working directory
WORKDIR /app

# Copy binaries and scripts
COPY geth beacon-chain-v5.1.0-linux-amd64 validator-v5.1.0-linux-amd64 prysmctl-v5.1.0-linux-amd64 config.yml start.sh ./

# Copy nodekey and config.toml
COPY nodekey /app/nodekey
COPY beaconkey /app/beaconkey
COPY config.toml /app/config.toml

# Make binaries and scripts executable
RUN chmod +x geth beacon-chain-v5.1.0-linux-amd64 validator-v5.1.0-linux-amd64 prysmctl-v5.1.0-linux-amd64 start.sh

# Clone and set up Bundler
#RUN git clone https://github.com/eth-infinitism/bundler.git /app/bundler && \
#    cd /app/bundler && \
#    yarn install --ignore-engines && \
#    yarn preprocess

# Expose necessary ports
EXPOSE 30304 8551 8545 13001 12001 4001 3501 7501 7001 8082 8083 3000


# Entry point
CMD ["/app/start.sh"]
