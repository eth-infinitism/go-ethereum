# Use the official Ubuntu image as the base
FROM ubuntu:22.04

# Set environment variables for non-interactive installs
ENV DEBIAN_FRONTEND=noninteractive

# Install any dependencies required by prysmctl
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

# Set up a working directory
WORKDIR /app

# Copy the prysmctl binary and your script into the container
COPY prysmctl-v5.1.0-linux-amd64 /app/
COPY scripts/generate-genesis.sh /app/scripts/
COPY scripts/genesis.json.template /app/scripts/
COPY scripts/config.yml /app/scripts/

# Make the binary and script executable
RUN chmod +x /app/prysmctl-v5.1.0-linux-amd64 /app/scripts/generate-genesis.sh

# Define the command to run the script
CMD ["/app/prysmctl-v5.1.0-linux-amd64"]
