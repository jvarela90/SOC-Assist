# SOC Assist — Production Dockerfile
# Build: docker build -t soc-assist .
# Run:   docker run -p 8000:8000 soc-assist

FROM python:3.13-slim

# System deps (needed for bcrypt C extension)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create data directory for persistent SQLite DB
RUN mkdir -p /data && chmod 777 /data

# Environment defaults (override via docker-compose or -e flags)
ENV SOC_DB_PATH=/data/soc_assist.db \
    SOC_SECRET_KEY=change-this-in-production \
    SOC_HOST=0.0.0.0 \
    SOC_PORT=8000 \
    SOC_WORKERS=1

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host $SOC_HOST --port $SOC_PORT --workers $SOC_WORKERS"]
