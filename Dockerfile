# By🇭🇷PhonkAlphabet
# Use Ubuntu 22.04 as base
FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-psutil \
    python3-bcc \
    yara \
    auditd \
    curl \
    git \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /opt/blueteam-aio

# Copy source code
COPY . .

# Install Python dependencies
RUN pip3 install --no-cache-dir fastapi uvicorn psutil

# Create necessary directories
RUN mkdir -p /etc/blueteam-aio /var/log/blueteam-aio /var/lib/blueteam-aio/models /var/lib/blueteam-aio/deception

# Expose API port
EXPOSE 8443

# Start the daemon and API server
CMD ["sh", "-c", "python3 src/daemon/core.py & python3 src/api/server.py"]
