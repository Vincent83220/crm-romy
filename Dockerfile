FROM python:3.11-slim AS base

WORKDIR /app

# Install Tesseract OCR with French language data
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr tesseract-ocr-fra tesseract-ocr-eng \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (cached layer — only rebuilds when requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt pytesseract Pillow

# Copy application code (secrets/volumes excluded via .dockerignore)
COPY . .

# Create runtime directories for bind mounts
RUN mkdir -p /app/data /app/backups /app/uploads /app/static

# Run as non-root for security
RUN useradd -r -u 1001 -g root crmuser && chown -R crmuser:root /app
USER 1001

EXPOSE 8001

# Healthcheck: the CRM serves /favicon.ico without auth
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/favicon.ico', timeout=3)" || exit 1

# Production-grade uvicorn: 1 worker for the file-based DB (avoid concurrent writes from multiple workers)
CMD ["python", "main.py"]