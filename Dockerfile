# Multi-stage to keep build tools out of the runtime image.
# builder installs gcc etc.; runtime copies only the compiled wheels.
FROM python:3.12-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/yuno-payments/chronospay"
LABEL security.pci-dss.scope="cardholder-data-environment"

# ca-certificates needed for TLS to upstream processors
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
WORKDIR /app
COPY main.py .

# Non-root. UID/GID 10001 — arbitrary but consistent across image rebuilds.
# Trivy flags containers that omit this; policy gate blocks on that finding.
RUN groupadd --gid 10001 chronospay \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /sbin/nologin chronospay
USER 10001:10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
