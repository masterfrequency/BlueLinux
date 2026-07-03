# By🇭🇷PhonkAlphabet
# ============================================================
# Stage 1: Builder — install dependencies, no runtime overhead
# ============================================================
FROM python:3.10-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build-time system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the entire repo
COPY . .

# Install Python dependencies
RUN pip3 install --no-cache-dir fastapi uvicorn psutil

# ============================================================
# Stage 2: Runtime — minimal, hardened, non-root
# ============================================================
FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# BLUETEAM_API_KEY — auto-generated as 32-char hex if unset
ENV BLUETEAM_API_KEY=""

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    iptables \
    yara \
    auditd \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and group
RUN groupadd -r blueteam -g 1001 && \
    useradd -r -g blueteam -u 1001 -d /opt/blueteam-aio -s /sbin/nologin blueteam

WORKDIR /opt/blueteam-aio

# Copy installed Python packages and binaries from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy the source code from builder
COPY --from=builder /build .

# Create and own runtime directories
RUN mkdir -p /etc/blueteam-aio /var/log/blueteam-aio /var/lib/blueteam-aio/models /var/lib/blueteam-aio/deception && \
    chown -R blueteam:blueteam /opt/blueteam-aio /etc/blueteam-aio /var/log/blueteam-aio /var/lib/blueteam-aio

# Expose API port
EXPOSE 8443

# Healthcheck — probes API every 30s
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8443/health || exit 1

# Drop privileges
USER blueteam

# Start daemon and API server; auto-generate BLUETEAM_API_KEY if empty
CMD ["sh", "-c", "if [ -z \"$BLUETEAM_API_KEY\" ]; then export BLUETEAM_API_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(16))'); fi; python3 src/daemon/core.py & python3 src/api/server.py"]
