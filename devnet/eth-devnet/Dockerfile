FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y software-properties-common wget curl libgomp1 build-essential git gnupg openssl && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js (required for Bundler)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g yarn

# Set working directory
WORKDIR /app

# Copy binaries and scripts into the image
COPY geth \
     beacon-chain-v5.1.0-linux-amd64 \
     validator-v5.1.0-linux-amd64 \
     prysmctl-v5.1.0-linux-amd64 \
     scripts/config.yml \
     start.sh ./

# Make binaries and scripts executable
RUN chmod +x geth \
               beacon-chain-v5.1.0-linux-amd64 \
               validator-v5.1.0-linux-amd64 \
               prysmctl-v5.1.0-linux-amd64 \
               start.sh

# Clone and set up Bundler
RUN git clone https://github.com/eth-infinitism/bundler.git /app/bundler && \
    cd /app/bundler && \
    yarn install --ignore-engines && \
    yarn preprocess

# Expose necessary ports (common ports; actual mapping happens in docker-compose)
EXPOSE 8545 8546 8551 6060 30303 30304 \
       13000 13001 12000 12001 \
       4000 4001 3500 3501 \
       7000 7001 7500 7501 \
       8080 8081 8082 8083 \
       3000

# Entry point
CMD ["/app/start.sh"]
