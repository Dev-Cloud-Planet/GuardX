# ── Stage 1: Build Python dependencies ───────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# ── Stage 2: Runtime ─────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="DevCloudPlanet"
LABEL description="GuardX AI - Agente de seguridad con IA"

# Install nmap and utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    nmap \
    curl \
    ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install nuclei (optional - won't fail the build if unavailable)
RUN ARCH=$(dpkg --print-architecture) && \
    NUCLEI_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | grep "browser_download_url.*linux_${ARCH}.zip" \
    | head -1 \
    | cut -d '"' -f 4) && \
    if [ -n "$NUCLEI_URL" ]; then \
    curl -sL "$NUCLEI_URL" -o /tmp/nuclei.zip && \
    apt-get update && apt-get install -y --no-install-recommends unzip && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f /tmp/nuclei.zip && \
    apt-get purge -y unzip && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*; \
    else \
    echo "WARNING: Could not download nuclei, skipping..."; \
    fi

# Copy Python venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user and tmp dirs (before switching to non-root)
RUN groupadd -r guardx && useradd -r -g guardx -m guardx && \
    mkdir -p /tmp/gunicorn && chown guardx:guardx /tmp/gunicorn

# Set working directory
WORKDIR /app

# Copy project files
COPY --chown=guardx:guardx . .

# Switch to non-root user
USER guardx

# Expose web panel port
EXPOSE 5000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Run with gunicorn + gevent-websocket for production WebSocket support
CMD ["gunicorn", "--worker-class", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "--workers", "1", "--bind", "0.0.0.0:5000", "--timeout", "300", "--keep-alive", "65", "--worker-tmp-dir", "/tmp/gunicorn", "--no-sendfile", "web.app:app"]
