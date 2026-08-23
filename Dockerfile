# Dockerfile for SAML Metadata Parser
# Azure Container Apps deployment

FROM your-acr-name.azurecr.io/python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# Install system dependencies required for lxml
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2-dev \
    libxslt1-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# OpenShift compatibility — REQUIRED, not cosmetic.
#
# `restricted-v2` IGNORES the USER line below and runs the container as an
# arbitrary UID from the namespace's assigned range, always in GID 0. With only
# `chown -R appuser:appuser`, that UID is in neither the owning user nor the
# owning group, so /app is not even READABLE by it and gunicorn dies at import:
#
#   PermissionError: [Errno 13] Permission denied: '/app/saml_ui_parser_logic.py'
#
# Proven on the-cluster 2026-08-13 — and note it failed on a READ, in a tool that
# writes nothing. The blocker is not the "writes next to app.py" pattern the
# survey described; it applies to every image built this way.
#
# Giving group 0 the same rights as the owner is the standard OpenShift image
# convention and is a no-op on ACA, which honours USER appuser normally.
RUN chgrp -R 0 /app && chmod -R g=u /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check — hits the public login page (no auth required)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/login', timeout=5)" || exit 1

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--timeout", "120", "app:app"]
